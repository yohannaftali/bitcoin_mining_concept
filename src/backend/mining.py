"""
Stratum v1 CPU miner with NerdMiner_v2 parity.

This module implements a Bitcoin solo mining client using the Stratum v1 protocol.
It delegates protocol operations to stratum.py helpers and focuses on:
- Multi-process mining workers
- Job queue management with chunked nonce ranges (NONCE_PER_JOB)
- Submit tracking with incrementing IDs
- Session reporting and pool API integration
- Optional keepalive via mining.suggest_difficulty
- Status HTTP server for monitoring

Usage:
    python -m src.backend.miner --host public-pool.io --port 21496 --worker ADDRESS --submit
"""

import argparse
import hashlib
import http.server
import json
import logging
import multiprocessing
import os
import queue
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.request
import calendar
import datetime
from binascii import hexlify, unhexlify
from typing import Optional, Tuple, Dict, Any

try:
    import psutil
except ImportError:
    psutil = None

# Import stratum protocol helpers
try:
    from . import stratum as stratum_proto
except ImportError:
    import stratum as stratum_proto

# Constants
VERSION = "0.1.0"
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "log"))
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
logger = logging.getLogger("miner")
logger.setLevel(logging.DEBUG)

# Console handler (default formatting, will be replaced if --serial-compat enabled)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_fmt = logging.Formatter("[%(levelname)s] %(message)s")
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)

# File handler for detailed stratum logs
stratum_log_path = os.path.join(LOG_DIR, "stratum.log")
file_handler = logging.FileHandler(stratum_log_path, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(file_fmt)
logger.addHandler(file_handler)


class SerialCompatFormatter(logging.Formatter):
    """Arduino Serial.print-style formatter: plain message, no timestamp/level."""

    def format(self, record):
        return record.getMessage()


def enable_serial_compat_logging():
    """Switch console logging to Arduino Serial-style output (no timestamps, plain text)."""
    global console_handler
    # Replace the formatter on the existing console handler
    console_handler.setFormatter(SerialCompatFormatter())
    # Make console handler show DEBUG too (Arduino Serial shows everything)
    console_handler.setLevel(logging.DEBUG)


def double_sha256(data: bytes) -> bytes:
    """Compute double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def calc_merkle_root(coinbase_bytes: bytes, merkle_branches: list) -> bytes:
    """Calculate merkle root from coinbase and branches."""
    h = double_sha256(coinbase_bytes)
    for branch_hex in (merkle_branches or []):
        h = double_sha256(h + unhexlify(branch_hex))
    return h


def build_block_header(version: int, prevhash_hex: str, merkle_root: bytes, ntime: int, nbits: int, nonce: int) -> bytes:
    """Build 80-byte block header."""
    header = b""
    header += struct.pack("<I", version)
    header += unhexlify(prevhash_hex)[::-1]  # reverse for little-endian
    header += merkle_root[::-1]  # reverse merkle root
    header += struct.pack("<I", ntime)
    header += struct.pack("<I", nbits)
    header += struct.pack("<I", nonce)
    return header


def diff_from_target(hash_bytes: bytes) -> float:
    """Calculate difficulty from a hash (interpreted as target)."""
    # Interpret hash as 256-bit number (little-endian)
    hash_int = int.from_bytes(hash_bytes, byteorder="little")
    if hash_int == 0:
        return float("inf")
    # Bitcoin difficulty 1 target
    diff1_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    return diff1_target / hash_int


def check_hash_meets_target(hash_bytes: bytes, target_bytes: bytes) -> bool:
    """Check if hash <= target (both as 256-bit integers, little-endian)."""
    hash_int = int.from_bytes(hash_bytes, byteorder="little")
    target_int = int.from_bytes(target_bytes, byteorder="little")
    return hash_int <= target_int


def worker_chunk_search(job_pool, nonce_start, nonce_count, version, prevhash_hex, merkle_root, ntime, nbits, target, result_q):
    """
    Worker process that searches a chunk of nonce space.
    Mimics NerdMiner_v2 job-based mining.
    """
    best_diff = 0.0
    for nonce in range(nonce_start, nonce_start + nonce_count):
        header = build_block_header(
            version, prevhash_hex, merkle_root, ntime, nbits, nonce)
        hash_result = double_sha256(header)

        # Calculate difficulty
        diff = diff_from_target(hash_result)
        if diff > best_diff:
            best_diff = diff

        # Check if it meets target
        if check_hash_meets_target(hash_result, target):
            # Found a valid share
            result_q.put({
                "type": "share",
                "job_pool": job_pool,
                "nonce": nonce,
                "hash": hash_result,
                "diff": diff,
                "nonce_count": nonce - nonce_start + 1
            })
            return  # Stop searching this chunk

    # Report completed chunk
    result_q.put({
        "type": "done",
        "job_pool": job_pool,
        "nonce_count": nonce_count,
        "best_diff": best_diff
    })


class StratumMiner:
    def __init__(self, host, port, worker, password="x", use_tls=False, submit=False,
                 procs=None, max_nonce=None, report_interval=30, report_pool=False,
                 preserve_worker=False, status_port: int = 0, cpus=None,
                 nonce_per_job: int = 4096, jobs_per_notify: int = 4,
                 start_nonce: int = None, random_nonce: bool = False,
                 suggest_difficulty: float = None, keepalive_interval: int = 30,
                 serial_compat: bool = False):
        """
        Initialize Stratum miner.

        Args:
            host: Pool hostname
            port: Pool port
            worker: Worker name (BTC address or user.worker)
            password: Worker password (default 'x')
            use_tls: Use TLS/SSL connection
            submit: Actually submit shares to pool
            procs: Number of worker processes (default: CPU count - 1)
            max_nonce: Maximum total nonces to search (None = unlimited)
            report_interval: Seconds between status reports
            report_pool: Query pool API for stats
            preserve_worker: Keep full worker string in auth
            status_port: HTTP status server port (0 = disabled)
            cpus: CPU affinity for workers (comma-separated or list)
            nonce_per_job: Nonce range per job chunk (NerdMiner parity)
            jobs_per_notify: Number of jobs to queue per notify
            start_nonce: Starting nonce value
            random_nonce: Use random nonce allocation
            suggest_difficulty: Difficulty to suggest to pool
            keepalive_interval: Keepalive suggest_difficulty interval (seconds, 0=disabled)
            serial_compat: Enable Arduino Serial.print-style logging (no timestamps)
        """
        self.host = host
        self.port = port
        self.worker = worker
        self.password = password
        self.use_tls = use_tls
        self.submit = submit
        self.procs = procs if procs is not None else max(
            1, multiprocessing.cpu_count() - 1)
        self.max_nonce = max_nonce
        self.report_interval = report_interval
        self.report_pool = report_pool
        self.preserve_worker = preserve_worker
        self.status_port = status_port
        self.cpus = cpus
        self.serial_compat = serial_compat

        # Enable Arduino-style logging if requested
        if self.serial_compat:
            enable_serial_compat_logging()

        # NerdMiner parity options
        self.nonce_per_job = int(nonce_per_job)
        self.jobs_per_notify = int(jobs_per_notify)
        # NerdMiner default
        self.start_nonce = start_nonce if start_nonce is not None else 0xDA54E700
        self.random_nonce = random_nonce
        self.suggest_difficulty = suggest_difficulty
        self.keepalive_interval = keepalive_interval

        # State
        self.sock = None
        self.extranonce1 = None
        self.extranonce2_size = 0
        self.auth_user = None
        self._next_submit_id = 3  # Start after subscribe(1) and authorize(2)
        self._submissions = {}  # Map submit_id -> metadata
        self._last_extranonce2 = None
        self.pool_difficulty = 1.0  # Track current pool difficulty for Arduino-style logging

        # Mining stats
        self.hash_count = 0
        self.start_time = None
        self.shares_found = 0
        self.valids_found = 0
        self.best_diff = 0.0

        # Reporter and status server
        self._reporter_thread = None
        self._status_server = None
        self._status_thread = None
        self._stop_event = threading.Event()
        self._keepalive_thread = None

        # Track worker PIDs for affinity
        self.active_proc_pids = []

    def connect(self):
        """Establish socket connection to pool."""
        if self.serial_compat:
            logger.info("")
            logger.info("Client not connected, trying to connect...")
            logger.info("Connecting to: %s:%d", self.host, self.port)
        else:
            logger.info("Connecting to %s:%d (TLS: %s)",
                        self.host, self.port, self.use_tls)

        raw_sock = socket.create_connection((self.host, self.port), timeout=10)

        if self.use_tls:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(
                raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock

        if self.serial_compat:
            logger.info("Connected!")
        else:
            logger.info("Connected to pool")

    def subscribe_and_authorize(self):
        """Send mining.subscribe and mining.authorize."""
        if self.serial_compat:
            logger.info("")
            logger.info("[WORKER] STEP 1: Pool server connection (SUBSCRIBE)")
        else:
            logger.info("Subscribing to pool...")

        # Send subscribe using stratum helpers
        subscribe_result, new_id = stratum_proto.tx_mining_subscribe(
            self.sock,
            VERSION,
            curr_id=1,
            timeout=10.0,
            serial_compat=self.serial_compat
        )

        if not subscribe_result:
            raise RuntimeError("Failed to subscribe to pool")

        self.extranonce1 = subscribe_result.extranonce1
        self.extranonce2_size = subscribe_result.extranonce2_size

        logger.info("Subscribe successful: extranonce1=%s, extranonce2_size=%d",
                    self.extranonce1, self.extranonce2_size)

        # Authorize
        if self.preserve_worker:
            auth_user = self.worker
        else:
            # Strip .worker suffix if present
            auth_user = self.worker.split(
                ".")[0] if "." in self.worker else self.worker

        self.auth_user = auth_user

        if self.serial_compat:
            logger.info("")
            logger.info("[WORKER] STEP 2: Pool authorize work (Block Info)")
            logger.info("   Worker: %s", auth_user)
        else:
            logger.info("Authorizing as: %s", auth_user)

        auth_id = stratum_proto.tx_mining_auth(
            self.sock, auth_user, self.password, new_id, serial_compat=self.serial_compat
        )

        if not self.serial_compat:
            logger.info("Authorization sent (id=%d)", auth_id)

        # Start keepalive thread if configured
        if self.keepalive_interval > 0:
            self._start_keepalive(auth_id)

    def _start_keepalive(self, initial_id: int):
        """Start background keepalive thread using suggest_difficulty."""
        def keepalive_loop():
            curr_id = initial_id
            while not self._stop_event.is_set():
                time.sleep(self.keepalive_interval)
                if self._stop_event.is_set():
                    break

                try:
                    difficulty = self.suggest_difficulty if self.suggest_difficulty else 0.00015
                    curr_id = stratum_proto.tx_suggest_difficulty(
                        self.sock, difficulty, curr_id, serial_compat=self.serial_compat
                    )
                    if not self.serial_compat:
                        logger.debug(
                            "Sent keepalive suggest_difficulty=%.6f", difficulty)
                except Exception as e:
                    logger.warning("Keepalive failed: %s", e)
                    break

        self._keepalive_thread = threading.Thread(
            target=keepalive_loop, daemon=True, name="Keepalive")
        self._keepalive_thread.start()

        if self.serial_compat:
            logger.info("Started keepalive thread")
        else:
            logger.info("Started keepalive thread (interval=%ds)",
                        self.keepalive_interval)

    def _read_line(self, timeout=5.0) -> Optional[str]:
        """Read a single line from socket."""
        buf = bytearray()
        try:
            self.sock.settimeout(timeout)
            while True:
                chunk = self.sock.recv(1)
                if not chunk:
                    break
                buf.extend(chunk)
                if chunk == b"\n":
                    break
        except Exception:
            return None

        try:
            return buf.decode(errors="replace")
        except Exception:
            return None

    def handle_notify(self, notify_obj: stratum_proto.MiningJob, job_pool: int, nonce_pool: int, job_q: queue.Queue):
        """
        Handle mining.notify by creating job chunks.

        This mimics NerdMiner_v2's job allocation:
        - Build coinbase and merkle root
        - Create multiple job chunks (jobs_per_notify)
        - Each chunk covers nonce_per_job nonces
        """
        # Extract notify parameters
        job_id = notify_obj.job_id
        prevhash = notify_obj.prev_block_hash
        coinb1 = notify_obj.coinb1
        coinb2 = notify_obj.coinb2
        merkle_branch = notify_obj.merkle_branch
        version = int(notify_obj.version, 16) if isinstance(
            notify_obj.version, str) else int(notify_obj.version)
        nbits = int(notify_obj.nbits, 16) if isinstance(
            notify_obj.nbits, str) else int(notify_obj.nbits)
        ntime = int(notify_obj.ntime, 16) if isinstance(
            notify_obj.ntime, str) else int(notify_obj.ntime)

        logger.info("New job: %s (clean=%s)", job_id, notify_obj.clean_jobs)

        # Build extranonce2 (NerdMiner convention: start at 1, zero-padded)
        size = self.extranonce2_size if self.extranonce2_size else 4
        if size == 2:
            extranonce2 = "0001"
        elif size == 4:
            extranonce2 = "00000001"
        elif size == 8:
            extranonce2 = "0000000000000001"
        else:
            extranonce2 = "{:0{width}x}".format(1, width=size * 2)

        # Remember extranonce2 for submits
        self._last_extranonce2 = extranonce2

        # Build coinbase
        coinbase_hex = coinb1 + self.extranonce1 + extranonce2 + coinb2
        coinbase_bytes = unhexlify(coinbase_hex)

        # Calculate merkle root
        merkle_root = calc_merkle_root(coinbase_bytes, merkle_branch)

        # Calculate target from nbits
        # nbits format: 0x1d00ffff -> target = 0x00ffff * 2^(8*(0x1d - 3))
        exponent = nbits >> 24
        mantissa = nbits & 0xFFFFFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))

        target = target_int.to_bytes(32, byteorder="big")

        logger.debug("Target: %s", hexlify(target).decode())
        logger.debug("Merkle root: %s", hexlify(merkle_root[::-1]).decode())

        # Clear job queue if clean_jobs
        if notify_obj.clean_jobs:
            while not job_q.empty():
                try:
                    job_q.get_nowait()
                except queue.Empty:
                    break

        # Create job chunks (NerdMiner-style)
        for _ in range(self.jobs_per_notify):
            job_q.put((job_pool, nonce_pool, self.nonce_per_job,
                      version, prevhash, merkle_root, ntime, nbits, target))
            nonce_pool += self.nonce_per_job

        return nonce_pool

    def submit_share(self, job_id: str, ntime: int, nonce: int, hash_result: bytes, diff: float):
        """Submit a share to the pool."""
        if not self.submit:
            logger.info(
                "SHARE FOUND (not submitting): nonce=0x%08x diff=%.2f", nonce, diff)
            return

        # Use saved extranonce2
        extranonce2_hex = self._last_extranonce2 if self._last_extranonce2 else "00000001"

        # Create MiningJob object for submit
        mJob = stratum_proto.MiningJob(
            job_id=job_id,
            ntime="{:08x}".format(ntime),
            prev_block_hash="",
            coinb1="",
            coinb2="",
            merkle_branch=[],
            version="",
            nbits="",
            clean_jobs=False
        )

        nonce_hex = "{:08x}".format(nonce)

        try:
            submit_id = self._next_submit_id
            sent_id = stratum_proto.tx_mining_submit(
                self.sock,
                self.auth_user,
                mJob,
                extranonce2_hex,
                nonce_hex,
                submit_id,
                serial_compat=self.serial_compat
            )

            # Update next submit ID
            if sent_id > submit_id:
                self._next_submit_id = sent_id + 1
            else:
                self._next_submit_id += 1

            # Track submission
            self._submissions[sent_id] = {
                "nonce": nonce,
                "diff": diff,
                "hash": hexlify(hash_result[::-1]).decode(),
                "time": time.time()
            }

            if self.serial_compat:
                # Arduino-style output
                logger.info("   - Current diff share: %.12f", diff)
                logger.info("   - Current pool diff : %.12f",
                            self.pool_difficulty)
                logger.info("   - TX SHARE: %s",
                            hexlify(hash_result[::-1]).decode())
            else:
                logger.info("SUBMIT: id=%d nonce=0x%08x diff=%.2f",
                            sent_id, nonce, diff)

            # Update best diff
            if diff > self.best_diff:
                self.best_diff = diff

        except Exception as e:
            logger.error("Failed to submit share: %s", e)

    def run(self):
        """Main mining loop."""
        self.start_time = time.time()

        # Start status server
        if self.status_port:
            self.start_status_server()

        # Start reporter thread
        self._start_reporter()

        # Connect and authorize
        self.connect()
        self.subscribe_and_authorize()

        # Setup worker processes
        job_q = queue.Queue()
        result_q = multiprocessing.Queue()
        workers = []

        # Track job allocation
        job_pool = 0
        nonce_pool = self.start_nonce
        current_job_id = None
        current_ntime = 0

        # Apply CPU affinity if specified
        if self.cpus and psutil:
            cpu_list = []
            if isinstance(self.cpus, str):
                cpu_list = [int(x.strip())
                            for x in self.cpus.split(",") if x.strip()]
            elif isinstance(self.cpus, list):
                cpu_list = [int(x) for x in self.cpus]

            if cpu_list:
                logger.info("Setting CPU affinity: %s", cpu_list)

        try:
            logger.info("Starting %d worker processes...", self.procs)

            # Main mining loop
            while True:
                # Check for pool messages
                self.sock.settimeout(0.1)
                try:
                    line = self._read_line(timeout=0.1)
                    if line:
                        method_type = stratum_proto.parse_mining_method(line)

                        if method_type == stratum_proto.MINING_NOTIFY:
                            notify_obj = stratum_proto.parse_mining_notify(
                                line)
                            if notify_obj:
                                current_job_id = notify_obj.job_id
                                current_ntime = int(notify_obj.ntime, 16) if isinstance(
                                    notify_obj.ntime, str) else int(notify_obj.ntime)
                                job_pool += 1
                                nonce_pool = self.handle_notify(
                                    notify_obj, job_pool, nonce_pool, job_q)

                        elif method_type == stratum_proto.MINING_SET_DIFFICULTY:
                            difficulty = stratum_proto.parse_mining_set_difficulty(
                                line)
                            if difficulty:
                                self.pool_difficulty = difficulty
                                if self.serial_compat:
                                    logger.info(
                                        "Pool difficulty set to: %.6f", difficulty)
                                else:
                                    logger.info(
                                        "Difficulty set to: %.6f", difficulty)

                        elif method_type == stratum_proto.STRATUM_SUCCESS:
                            # Response to a previous submit
                            submit_id = stratum_proto.parse_extract_id(line)
                            if submit_id in self._submissions:
                                meta = self._submissions.pop(submit_id)
                                self.shares_found += 1
                                logger.info("ACCEPTED: id=%d diff=%.2f",
                                            submit_id, meta["diff"])

                except socket.timeout:
                    pass

                # Start/maintain worker processes
                if len(workers) < self.procs:
                    try:
                        job_data = job_q.get_nowait()
                        p = multiprocessing.Process(
                            target=worker_chunk_search,
                            args=job_data + (result_q,)
                        )
                        p.start()
                        workers.append(p)
                        self.active_proc_pids.append(p.pid)

                        # Apply CPU affinity if configured
                        if self.cpus and psutil and cpu_list:
                            try:
                                proc = psutil.Process(p.pid)
                                proc.cpu_affinity(cpu_list)
                            except Exception as e:
                                logger.debug(
                                    "Failed to set affinity for PID %d: %s", p.pid, e)

                    except queue.Empty:
                        pass

                # Collect worker results
                try:
                    while True:
                        result = result_q.get_nowait()

                        if result["type"] == "share":
                            self.hash_count += result["nonce_count"]
                            self.submit_share(
                                current_job_id,
                                current_ntime,
                                result["nonce"],
                                result["hash"],
                                result["diff"]
                            )
                        elif result["type"] == "done":
                            self.hash_count += result["nonce_count"]
                            if result["best_diff"] > self.best_diff:
                                self.best_diff = result["best_diff"]

                except queue.Empty:
                    pass

                # Clean up finished workers
                workers = [w for w in workers if w.is_alive()]
                self.active_proc_pids = [
                    p.pid for p in workers if p.is_alive()]

                # Check max_nonce limit
                if self.max_nonce and self.hash_count >= self.max_nonce:
                    logger.info("Reached max_nonce limit: %d", self.hash_count)
                    break

                time.sleep(0.01)

        except KeyboardInterrupt:
            logger.info("Interrupted by user")

        finally:
            logger.info("Shutting down...")
            self._stop_event.set()

            # Stop workers
            for w in workers:
                if w.is_alive():
                    w.terminate()
                    w.join(timeout=1)

            # Stop threads
            if self._keepalive_thread:
                self._keepalive_thread.join(timeout=2)

            # Close socket
            if self.sock:
                self.sock.close()

            # Stop status server
            self.stop_status_server()

            logger.info("Mining session complete")
            logger.info("Total hashes: %d", self.hash_count)
            logger.info("Shares found: %d", self.shares_found)
            logger.info("Best difficulty: %.6f", self.best_diff)

    # Reporter and status server methods
    def _start_reporter(self):
        """Start background reporter thread."""
        def reporter_loop():
            while not self._stop_event.is_set():
                time.sleep(self.report_interval)
                if self._stop_event.is_set():
                    break

                self._write_status_snapshot()

        self._reporter_thread = threading.Thread(
            target=reporter_loop, daemon=True, name="Reporter")
        self._reporter_thread.start()
        logger.debug("Started reporter thread")

    def _build_status(self) -> dict:
        """Build status snapshot."""
        uptime = time.time() - self.start_time if self.start_time else 0
        est_hs = self.hash_count / uptime if uptime > 0 else 0.0

        status = {
            "running": True,
            "auth_user": self.auth_user,
            "worker": self.worker,
            "uptime_seconds": uptime,
            "hash_count": self.hash_count,
            "est_hashrate_Hs": est_hs,
            "shares": self.shares_found,
            "best_diff": self.best_diff,
            "active_procs": len(self.active_proc_pids),
            "worker_pids": self.active_proc_pids,
            "status_port": self.status_port
        }

        # Add pool data if requested
        if self.report_pool and self.auth_user:
            try:
                url = f"https://public-pool.io:40557/api/client/{self.auth_user}"
                with urllib.request.urlopen(url, timeout=5) as r:
                    data = json.loads(r.read().decode())
                    status["pool"] = data
            except Exception as e:
                status["pool_error"] = str(e)

        return status

    def _write_status_snapshot(self):
        """Write status to JSON file."""
        status_path = os.path.join(LOG_DIR, "session_status.json")
        status = self._build_status()

        tmp = status_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(status, fh, indent=2)

        try:
            os.replace(tmp, status_path)
        except Exception:
            try:
                os.rename(tmp, status_path)
            except Exception:
                logger.debug("Failed to write status snapshot", exc_info=True)

        logger.debug("Status: hashes=%d rate=%.2f H/s",
                     status["hash_count"], status["est_hashrate_Hs"])

    def start_status_server(self):
        """Start HTTP status server."""
        if not self.status_port or self._status_server:
            return

        miner_self = self

        class _StatusHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/status":
                    status = miner_self._build_status()
                    data = json.dumps(status).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

        server = socketserver.ThreadingTCPServer(
            ("0.0.0.0", self.status_port), _StatusHandler)
        self._status_server = server

        def _serve():
            server.serve_forever()

        self._status_thread = threading.Thread(
            target=_serve, daemon=True, name="StatusHTTP")
        self._status_thread.start()
        logger.info("Status server started on port %d", self.status_port)

    def stop_status_server(self):
        """Stop HTTP status server."""
        if not self._status_server:
            return

        try:
            self._status_server.shutdown()
            self._status_server.server_close()
        except Exception:
            logger.debug("Failed to stop status server", exc_info=True)

        self._status_server = None
        self._status_thread = None


def parse_args():
    p = argparse.ArgumentParser(
        description="Stratum v1 CPU miner (educational)")
    p.add_argument("--host", required=True, help="Pool host")
    p.add_argument("--port", type=int, required=True, help="Pool port")
    p.add_argument("--worker", required=True,
                   help="Worker name (address.worker)")
    p.add_argument("--pass", dest="password",
                   default="x", help="Worker password")
    p.add_argument("--tls", action="store_true", help="Use TLS")
    p.add_argument("--submit", action="store_true",
                   help="Submit shares to pool")
    p.add_argument("--procs", type=int, default=None,
                   help="Number of worker processes")
    p.add_argument("--max-nonce", type=int, default=None,
                   help="Maximum nonces to search")
    p.add_argument("--report-interval", type=int, default=30,
                   help="Status report interval (seconds)")
    p.add_argument("--report-pool", action="store_true",
                   help="Query pool API for stats")
    p.add_argument("--preserve-worker", action="store_true",
                   help="Preserve full worker string")
    p.add_argument("--status-port", type=int, default=0,
                   help="HTTP status server port")
    p.add_argument("--cpus", type=str, default=None,
                   help="CPU affinity (comma-separated core indices)")
    p.add_argument("--nonce-per-job", type=int, default=4096,
                   help="Nonce range per job chunk")
    p.add_argument("--jobs-per-notify", type=int,
                   default=4, help="Job chunks per notify")
    p.add_argument("--start-nonce", type=int, default=None,
                   help="Starting nonce value")
    p.add_argument("--random-nonce", action="store_true",
                   help="Use random nonce allocation")
    p.add_argument("--suggest-difficulty", type=float,
                   default=None, help="Difficulty to suggest")
    p.add_argument("--keepalive-interval", type=int, default=30,
                   help="Keepalive interval (seconds, 0=disabled)")
    p.add_argument("--serial-compat", action="store_true",
                   help="Enable Arduino Serial.print-style logging (no timestamps)")
    return p.parse_args()


if __name__ == "__main__":
    # Required for multiprocessing on Windows
    multiprocessing.freeze_support()
    
    args = parse_args()

    miner = StratumMiner(
        host=args.host,
        port=args.port,
        worker=args.worker,
        password=args.password,
        use_tls=args.tls,
        submit=args.submit,
        procs=args.procs,
        max_nonce=args.max_nonce,
        report_interval=args.report_interval,
        report_pool=args.report_pool,
        preserve_worker=args.preserve_worker,
        status_port=args.status_port,
        cpus=args.cpus,
        nonce_per_job=args.nonce_per_job,
        jobs_per_notify=args.jobs_per_notify,
        start_nonce=args.start_nonce,
        random_nonce=args.random_nonce,
        suggest_difficulty=args.suggest_difficulty,
        keepalive_interval=args.keepalive_interval,
        serial_compat=args.serial_compat
    )

    try:
        miner.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
