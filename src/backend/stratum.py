"""
Lightweight Stratum helpers ported from NerdMiner_v2 Arduino code.

This module implements basic JSON-RPC message creation/parsing for
mining.subscribe, mining.authorize, mining.notify, mining.set_difficulty,
mining.submit and mining.suggest_difficulty. It mirrors the Arduino
implementation semantics so host-side tests can compare behavior.

Functions operate on a socket-like object that supports sendall(bytes)
and recv(bufsize) returning bytes. Lines are newline-terminated JSON
strings like the pool sends.

This file is intentionally small and dependency-free (stdlib only).
"""
from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("stratum")
logger.addHandler(logging.NullHandler())

# Emulate an unsigned 32-bit id rollover like the Arduino example
MAX_ID = 0xFFFFFFFF


def get_next_id(curr_id: int) -> int:
    """Return next JSON-RPC id, rolling to 1 on overflow.

    Matches the Arduino getNextId/ULONG_MAX behaviour.
    """
    if curr_id >= MAX_ID:
        return 1
    return curr_id + 1


def verify_payload(line: str) -> bool:
    if line is None:
        return False
    line = line.strip()
    return len(line) > 0


def check_error(doc: Dict[str, Any]) -> bool:
    """Return True if the JSON-RPC payload contains a non-empty error."""
    if not isinstance(doc, dict):
        return False
    if "error" not in doc:
        return False
    err = doc.get("error")
    # null or empty -> not an error
    if err is None:
        return False
    if isinstance(err, (list, dict)) and len(err) == 0:
        return False
    logger.error("ERROR: %s", err)
    return True


def _readline_from_socket(sock: socket.socket, timeout: Optional[float] = 5.0) -> Optional[str]:
    """Read a single line (terminated by \n) from a socket and return decoded text.

    Returns None on timeout or socket error.
    """
    buf = bytearray()
    try:
        sock.settimeout(timeout)
        while True:
            chunk = sock.recv(1)
            if not chunk:
                # connection closed
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


@dataclass
class MiningSubscribe:
    sub_details: str = ""
    extranonce1: str = ""
    extranonce2_size: int = 0


def parse_mining_subscribe(line: str) -> Optional[MiningSubscribe]:
    if not verify_payload(line):
        return None
    logger.debug("Received: %s", line)
    try:
        doc = json.loads(line)
    except Exception:
        return None
    if check_error(doc):
        return None
    res = doc.get("result")
    if not res:
        return None
    # result is [details, extranonce1, extranonce2_size]
    try:
        sub_details = res[0][0][1] if isinstance(
            res[0], list) and len(res[0]) > 0 else ""
        extranonce1 = res[1] if len(res) > 1 else ""
        extranonce2_size = int(res[2]) if len(res) > 2 else 0
    except Exception:
        return None

    m = MiningSubscribe(sub_details=sub_details,
                        extranonce1=extranonce1, extranonce2_size=extranonce2_size)
    return m


def tx_mining_subscribe(sock: socket.socket, current_version: str, curr_id: int = 1, timeout: float = 5.0, serial_compat: bool = False) -> Tuple[Optional[MiningSubscribe], int]:
    """Send mining.subscribe and read a single-line response.

    Returns (MiningSubscribe or None, new_id)
    """
    payload = {"id": curr_id, "method": "mining.subscribe",
               "params": [f"NerdMinerV2/{current_version}"]}
    text = json.dumps(payload, separators=(",", ":")) + "\n"

    if serial_compat:
        logger.info("  Sending  : mining.subscribe")
        logger.debug("%s", text.rstrip())
    else:
        logger.info("==> Mining subscribe")
        logger.debug("Sending: %s", text)

    try:
        sock.sendall(text.encode())
    except Exception:
        return None, curr_id
    line = _readline_from_socket(sock, timeout=timeout)
    if not line:
        return None, curr_id

    if serial_compat:
        logger.debug("  Received : %s", line)

    m = parse_mining_subscribe(line)
    return m, curr_id


def tx_mining_auth(sock: socket.socket, user: str, pwd: str, curr_id: int, serial_compat: bool = False) -> int:
    """Send mining.authorize. Does not wait for a specific response here (mirror Arduino).

    Returns the new id value used after sending.
    """
    new_id = get_next_id(curr_id)
    payload = {"params": [user, pwd],
               "id": new_id, "method": "mining.authorize"}
    text = json.dumps(payload, separators=(",", ":")) + "\n"

    if serial_compat:
        logger.info("  Sending  : mining.authorize")
        logger.debug("%s", text.rstrip())
    else:
        logger.info("==> Authorize")
        logger.debug("Sending: %s", text)

    try:
        sock.sendall(text.encode())
    except Exception:
        return curr_id
    return new_id


# parse mining method types
STRATUM_PARSE_ERROR = -1
STRATUM_SUCCESS = 0
STRATUM_UNKNOWN = 1
MINING_NOTIFY = 2
MINING_SET_DIFFICULTY = 3


def parse_mining_method(line: str) -> int:
    if not verify_payload(line):
        return STRATUM_PARSE_ERROR
    logger.debug("Receiving: %s", line)
    try:
        doc = json.loads(line)
    except Exception:
        return STRATUM_PARSE_ERROR
    if check_error(doc):
        return STRATUM_PARSE_ERROR
    if "method" not in doc:
        # no method -> could be a reply or error-null success
        if doc.get("error") is None:
            return STRATUM_SUCCESS
        return STRATUM_UNKNOWN
    m = doc.get("method")
    if m == "mining.notify":
        return MINING_NOTIFY
    if m == "mining.set_difficulty":
        return MINING_SET_DIFFICULTY
    return STRATUM_UNKNOWN


@dataclass
class MiningJob:
    job_id: str = ""
    prev_block_hash: str = ""
    coinb1: str = ""
    coinb2: str = ""
    merkle_branch: Any = field(default_factory=list)
    version: str = ""
    nbits: str = ""
    ntime: str = ""
    clean_jobs: bool = False


def parse_mining_notify(line: str) -> Optional[MiningJob]:
    logger.debug("Parsing Method [MINING NOTIFY]")
    if not verify_payload(line):
        return None
    try:
        doc = json.loads(line)
    except Exception:
        return None
    if "params" not in doc:
        return None
    p = doc["params"]
    try:
        m = MiningJob(
            job_id=str(p[0]),
            prev_block_hash=str(p[1]),
            coinb1=str(p[2]),
            coinb2=str(p[3]),
            merkle_branch=p[4],
            version=str(p[5]),
            nbits=str(p[6]),
            ntime=str(p[7]),
            clean_jobs=bool(p[8]) if len(p) > 8 else False,
        )
    except Exception:
        return None
    return m


def tx_mining_submit(sock: socket.socket, worker_name: str, mJob: MiningJob, extranonce2: str, nonce_hex: str, curr_id: int, serial_compat: bool = False) -> int:
    """Send mining.submit message and return the id used for this submit.

    `nonce_hex` should be a hex string (lower or upper). Returns the id used.
    """
    new_id = get_next_id(curr_id)
    params = [worker_name, mJob.job_id, extranonce2, mJob.ntime, nonce_hex]
    payload = {"id": new_id, "method": "mining.submit", "params": params}
    text = json.dumps(payload, separators=(",", ":")) + "\n"

    if serial_compat:
        logger.info("  Sending  : STRATUM SUBMIT OUT")
        logger.debug("%s", text.rstrip())
    else:
        logger.debug("Sending submit: %s", text)

    try:
        sock.sendall(text.encode())
    except Exception:
        return curr_id
    return new_id


def parse_mining_set_difficulty(line: str) -> Optional[float]:
    logger.debug("Parsing Method [SET DIFFICULTY]")
    if not verify_payload(line):
        return None
    try:
        doc = json.loads(line)
    except Exception:
        return None
    if "params" not in doc:
        return None
    try:
        difficulty = float(doc["params"][0])
    except Exception:
        return None
    logger.info("difficulty: %r", difficulty)
    return difficulty


def tx_suggest_difficulty(sock: socket.socket, difficulty: float, curr_id: int, serial_compat: bool = False) -> int:
    new_id = get_next_id(curr_id)
    # use a compact JSON representation; Arduino used %.10g formatting
    payload = {"id": new_id, "method": "mining.suggest_difficulty",
               "params": [difficulty]}
    text = json.dumps(payload, separators=(",", ":")) + "\n"

    if serial_compat:
        logger.info("  Sending  : KeepAlive suggest_difficulty")
        logger.debug("%s", text.rstrip())
    else:
        logger.debug("Sending suggest_difficulty: %s", text)

    try:
        sock.sendall(text.encode())
    except Exception:
        return curr_id
    return new_id


def parse_extract_id(line: str) -> int:
    try:
        doc = json.loads(line)
    except Exception:
        return 0
    if not isinstance(doc, dict):
        return 0
    return int(doc.get("id", 0))


__all__ = [
    "get_next_id",
    "verify_payload",
    "check_error",
    "tx_mining_subscribe",
    "parse_mining_subscribe",
    "tx_mining_auth",
    "parse_mining_method",
    "parse_mining_notify",
    "tx_mining_submit",
    "parse_mining_set_difficulty",
    "tx_suggest_difficulty",
    "parse_extract_id",
    "MiningSubscribe",
    "MiningJob",
]
