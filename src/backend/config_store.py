"""
Configuration store for miner profiles.
Provides load_configs, save_profile, and ensure_default_profile so the frontend can delegate profile persistence to the backend.
"""
import os
import json
import logging

logger = logging.getLogger('config_store')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
os.makedirs(CONFIG_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(CONFIG_DIR, 'miner_configs.json')


def load_configs():
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            if isinstance(data, dict) and ('address' in data or 'btc_address' in data or 'worker' in data):
                name = data.get('btc_address') or data.get('worker') or 'default'
                return {name: data}
            if isinstance(data, dict):
                return data
            return {}
    except Exception:
        logger.debug('Failed to load configs', exc_info=True)
        return {}


def save_profile(name: str, cfg: dict) -> bool:
    try:
        tmp = CONFIG_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh, indent=2)
        try:
            os.replace(tmp, CONFIG_PATH)
        except Exception:
            try:
                os.rename(tmp, CONFIG_PATH)
            except Exception:
                raise
        return True
    except Exception:
        logger.debug('Failed to save profile', exc_info=True)
        try:
            if os.path.exists(CONFIG_PATH + '.tmp'):
                os.remove(CONFIG_PATH + '.tmp')
        except Exception:
            pass
        return False


def ensure_default_profile():
    cfgs = load_configs()
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
    name = default_cfg['btc_address']
    save_profile(name, default_cfg)
