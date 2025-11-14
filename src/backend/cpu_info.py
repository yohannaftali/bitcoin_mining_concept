"""
CPU info utility for backend.
Provides a background sampler and helpers to get per-core percentages.
This lives in `src/backend` so frontend can import backend functions rather than touching psutil directly.
"""
import threading
try:
    import psutil
except Exception:
    psutil = None

_cached_percents = []
_sampler_thread = None
_sampler_stop = threading.Event()


def _cpu_sampler_loop(interval=0.12):
    global _cached_percents
    while not _sampler_stop.is_set():
        try:
            if psutil:
                try:
                    _cached_percents = psutil.cpu_percent(
                        percpu=True, interval=0.1)
                except Exception:
                    try:
                        _cached_percents = psutil.cpu_percent(percpu=True)
                    except Exception:
                        _cached_percents = []
            else:
                _cached_percents = []
        except Exception:
            _cached_percents = []
        # sleep a bit (interval controls sampling cadence)
        _sampler_stop.wait(interval)


def start_sampler(interval=0.12):
    """Start background sampler thread (idempotent)."""
    global _sampler_thread
    if _sampler_thread and _sampler_thread.is_alive():
        return
    _sampler_stop.clear()
    _sampler_thread = threading.Thread(target=_cpu_sampler_loop, args=(
        interval,), name='backend-cpu-sampler', daemon=True)
    _sampler_thread.start()


def stop_sampler():
    _sampler_stop.set()


def get_cached_percents():
    """Return the most-recent cached per-core percentages (may be empty list)."""
    return list(_cached_percents)


def sample_percents(interval=0.1):
    """Return a fresh per-core CPU percent sample (blocking for `interval` seconds if psutil supports it)."""
    if not psutil:
        return []
    try:
        return psutil.cpu_percent(percpu=True, interval=interval)
    except TypeError:
        # older psutil may not accept interval kwarg
        try:
            return psutil.cpu_percent(percpu=True)
        except Exception:
            return []
    except Exception:
        return []
