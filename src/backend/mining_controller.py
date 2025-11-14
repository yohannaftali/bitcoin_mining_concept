"""
Mining Controller - Business logic layer for frontend.
Provides interface to backend mining operations without UI dependencies.
"""

import json
import os
import subprocess
import sys
import threading
import importlib.util
import logging
import datetime
import calendar
import time
from typing import Optional, Dict, List, Tuple, Any

# Import backend modules
_backend_cpu = None
_backend_config = None

try:
    if importlib.util.find_spec('src.backend.cpu_info') is not None:
        _backend_cpu = importlib.import_module('src.backend.cpu_info')
        try:
            _backend_cpu.start_sampler()
        except Exception:
            pass
except Exception:
    _backend_cpu = None

try:
    if importlib.util.find_spec('src.backend.config_store') is not None:
        _backend_config = importlib.import_module('src.backend.config_store')
except Exception:
    _backend_config = None

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger('mining_controller')
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


class MiningController:
    """Controller for managing mining operations and configuration."""

    def __init__(self):
        self._miner_lock = threading.Lock()
        self._miner_process = None
        self._config_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'backend', 'config', 'miner_configs.json'))
        self._status_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'backend', 'log', 'session_status.json'))

    # === Miner Control ===

    def start_miner(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Start the Stratum miner as a subprocess.

        Args:
            config: Mining configuration dictionary

        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._miner_lock:
            if self._miner_process is not None and self._miner_process.poll() is None:
                return False, 'Miner already running'

            # Extract config values
            host = config.get('address') or config.get(
                'host') or 'public-pool.io'
            port = int(config.get('port') or 21496)
            worker = config.get('btc_address') or config.get(
                'worker') or 'worker'
            submit = bool(config.get('submit', True))
            cpus = config.get('cpus') or config.get('core')

            # Determine process count
            procs_cfg = config.get('procs')
            if procs_cfg is not None and str(procs_cfg) != '':
                try:
                    procs = int(procs_cfg)
                except Exception:
                    procs = 1
            else:
                procs = None
                if cpus:
                    if isinstance(cpus, list):
                        procs = len(cpus)
                    elif isinstance(cpus, str):
                        parts = [p for p in cpus.split(',') if p.strip() != '']
                        procs = len(parts)
                if procs is None:
                    procs = 1

            max_nonce = config.get('max_nonce')
            report_interval = int(config.get('report_interval', 5))
            report_pool = bool(config.get('report_pool', True))

            # Build command
            module_name = 'src.backend.mining'
            if importlib.util.find_spec(module_name) is not None:
                cmd = [sys.executable, '-m', module_name]
            else:
                script_path = os.path.abspath(os.path.join(
                    os.path.dirname(__file__), '..', 'backend', 'mining.py'))
                cmd = [sys.executable, script_path]

            cmd.extend(['--host', str(host), '--port', str(port),
                       '--worker', str(worker), '--procs', str(procs),
                        '--report-interval', str(report_interval)])

            if submit:
                cmd.append('--submit')
            if report_pool:
                cmd.append('--report-pool')
            if max_nonce:
                cmd.extend(['--max-nonce', str(max_nonce)])
            if cpus:
                if isinstance(cpus, list):
                    cpus_arg = ','.join(str(int(x)) for x in cpus)
                else:
                    cpus_arg = str(cpus)
                cmd.extend(['--cpus', cpus_arg])

            # Start process
            try:
                p = subprocess.Popen(cmd, cwd=os.getcwd())
                self._miner_process = p
                return True, f'Started (pid {p.pid})'
            except OSError as e:
                return False, f'Failed to start: {e}'

    def stop_miner(self) -> Tuple[bool, str]:
        """
        Stop the running miner process.

        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._miner_lock:
            if self._miner_process is None or self._miner_process.poll() is not None:
                self._miner_process = None
                return False, 'Not running'

            try:
                self._miner_process.terminate()
                try:
                    self._miner_process.wait(timeout=3)
                except Exception:
                    logger.debug('Timeout waiting for miner to stop; killing')
                    self._miner_process.kill()
                    self._miner_process.wait(timeout=2)
            except OSError as e:
                return False, f'Stop failed: {e}'

            self._miner_process = None
            return True, 'Stopped'

    def is_running(self) -> bool:
        """Check if miner is currently running."""
        with self._miner_lock:
            return self._miner_process is not None and self._miner_process.poll() is None

    # === Status & Monitoring ===

    def get_status(self) -> Dict[str, Any]:
        """
        Get current mining status.

        Returns:
            Status dictionary with mining metrics
        """
        status = self._read_status_json() or {}
        running = self.is_running()

        # Extract session info from pool data
        session_id = None
        pool = status.get('pool') or {}
        workers = pool.get('workers', []) if isinstance(pool, dict) else []
        best_ts = 0

        for w in workers:
            last = w.get('lastSeen')
            if not last:
                continue
            try:
                dt = datetime.datetime.fromisoformat(
                    last.replace('Z', '+00:00'))
                ts = dt.timestamp()
            except Exception:
                try:
                    ts = calendar.timegm(time.strptime(
                        last, '%Y-%m-%dT%H:%M:%SZ'))
                except Exception:
                    continue

            if ts > best_ts:
                best_ts = ts
                session_id = w.get('sessionId')

        return {
            'running': bool(running),
            'worker': status.get('authorize_user') or status.get('worker_arg') or session_id,
            'auth_user': status.get('auth_user'),
            'uptime_seconds': status.get('uptime_seconds'),
            'est_hashrate_Hs': status.get('est_hashrate_Hs'),
            'hashRate_human': status.get('est_hashrate_human'),
            'pool': status.get('pool'),
            'session_best_difficulty': status.get('session_best_difficulty'),
            'session_hashrate': status.get('session_hashrate'),
            'session_hashrate_human': status.get('session_hashrate_human'),
        }

    def get_cpu_cores(self) -> List[Dict[str, Any]]:
        """
        Get CPU core information with usage percentages.

        Returns:
            List of core info dicts: [{'id': 0, 'percent': 12.3, 'selected': False}, ...]
        """
        cores = []

        try:
            # Get CPU percentages
            if _backend_cpu:
                percents = _backend_cpu.get_cached_percents() or _backend_cpu.sample_percents()
            elif psutil:
                try:
                    percents = psutil.cpu_percent(percpu=True, interval=0.1)
                except TypeError:
                    percents = psutil.cpu_percent(percpu=True)
            else:
                percents = []

            # Get selected cores from config
            cfgs = self.load_configs()
            selected = []
            if cfgs:
                first = cfgs[next(iter(cfgs))]
                c = first.get('core') if first.get(
                    'core') is not None else first.get('cpus')
                if isinstance(c, str):
                    selected = [int(x)
                                for x in c.split(',') if x.strip() != '']
                elif isinstance(c, list):
                    selected = [int(x) for x in c]

            for i, p in enumerate(percents):
                cores.append({
                    'id': i,
                    'percent': p,
                    'selected': (i in selected)
                })
        except Exception as e:
            logger.debug(f'Failed to get CPU cores: {e}')

        return cores

    # === Configuration Management ===

    def load_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        Load saved mining configurations.

        Returns:
            Dictionary mapping profile names to config dicts
        """
        try:
            if _backend_config:
                return _backend_config.load_configs()
        except Exception:
            logger.debug(
                'backend.config_store.load_configs failed', exc_info=True)

        # Fallback: read directly
        if not os.path.exists(self._config_path):
            return {}

        try:
            with open(self._config_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
                if isinstance(data, dict) and ('address' in data or 'btc_address' in data or 'worker' in data):
                    name = data.get('btc_address') or data.get(
                        'worker') or 'default'
                    return {name: data}
                if isinstance(data, dict):
                    return data
                return {}
        except (OSError, ValueError, json.JSONDecodeError):
            logger.debug('Failed to load configs', exc_info=True)
            return {}

    def save_config(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Save a mining configuration profile.

        Args:
            name: Profile name
            config: Configuration dictionary

        Returns:
            True if saved successfully
        """
        try:
            if _backend_config:
                return _backend_config.save_profile(name, config)
        except Exception:
            logger.debug(
                'backend.config_store.save_profile failed', exc_info=True)

        try:
            os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
            with open(self._config_path + '.tmp', 'w', encoding='utf-8') as fh:
                json.dump(config, fh, indent=2)
            try:
                os.replace(self._config_path + '.tmp', self._config_path)
            except OSError:
                os.rename(self._config_path + '.tmp', self._config_path)
            return True
        except Exception:
            logger.debug('Failed to save profile', exc_info=True)
            try:
                if os.path.exists(self._config_path + '.tmp'):
                    os.remove(self._config_path + '.tmp')
            except OSError:
                pass
            return False

    def ensure_default_config(self):
        """Create default configuration if none exists."""
        try:
            if _backend_config:
                _backend_config.ensure_default_profile()
                return
        except Exception:
            logger.debug(
                'backend.config_store.ensure_default_profile failed', exc_info=True)

        cfgs = self.load_configs()
        if cfgs:
            return

        default_cfg = {
            'address': 'public-pool.io',
            'port': '21496',
            'btc_address': 'bc1qug6j3j2et4q02padn85edu7xlk0scrf8ue2h9d',
            'procs': '1',
            'report_pool': True,
            'report_interval': '5'
        }
        default_name = default_cfg['btc_address']
        self.save_config(default_name, default_cfg)

    def update_cpu_cores(self, cores: List[int]) -> Dict[str, Any]:
        """
        Update selected CPU cores in configuration.

        Args:
            cores: List of core IDs to use

        Returns:
            Result dictionary with 'ok' status
        """
        cfgs = self.load_configs()
        if not cfgs:
            return {'ok': False, 'msg': 'no saved profile'}

        name = next(iter(cfgs))
        cfg = cfgs[name]

        try:
            cfg['core'] = [int(x) for x in cores]
        except Exception:
            cfg['core'] = cores

        ok = self.save_config(name, cfg)
        result = {'ok': bool(ok)}

        # Try to apply affinity to running workers
        if psutil:
            try:
                status = self._read_status_json() or {}
                pids = status.get('worker_pids') or []
                applied = []
                failed = []

                for pid in pids:
                    try:
                        psutil.Process(int(pid)).cpu_affinity(
                            [int(x) for x in cores])
                        applied.append(int(pid))
                    except Exception as e:
                        failed.append({'pid': pid, 'error': str(e)})

                result['live_apply'] = {'applied': applied, 'failed': failed}
            except Exception as e:
                result['live_apply'] = {'error': str(e)}

        return result

    # === Private Helpers ===

    def _read_status_json(self) -> Optional[Dict[str, Any]]:
        """Read status JSON from backend log directory."""
        if not os.path.exists(self._status_path):
            return None

        try:
            with open(self._status_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except (OSError, ValueError, json.JSONDecodeError):
            logger.debug('Failed to read status json', exc_info=True)
            return None
