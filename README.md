# Bitcoin Mining Concept

Educational Bitcoin mining demonstration with Flet desktop UI.

This repository contains an educational host-side Stratum v1 miner and a modern desktop UI built with Flet to control it. It's designed for experimentation, diagnostics and learning about Bitcoin mining — not for production mining.

**Important:** CPU-based mining on Bitcoin mainnet is effectively impossible and will not be profitable. The code here is for learning and testing (use regtest or testnet when you want to submit blocks/shares).

## Architecture

The project uses a clean separation of concerns:

- **Frontend Layer** (`src/frontend/`)
  - `flet_ui.py` — Modern desktop UI built with Flet framework
  - `mining_controller.py` — Business logic layer that interfaces with backend
  - `FRONTEND_README.md` — Detailed frontend architecture documentation

- **Backend Layer** (`src/backend/`)
  - `mining.py` — Stratum v1 client with multiprocessing workers
  - `cpu_info.py` — CPU monitoring and affinity management
  - `config_store.py` — Configuration persistence
  - `config/miner_configs.json` — Saved mining profiles
  - `log/session_status.json` — Real-time mining session data
  - `log/stratum.log` — Detailed mining logs

## Included scripts

- `src/main.py` — Main entry point that launches the Flet desktop UI
- `src/backend/mining.py` — Stratum v1 miner with multiprocessing support
- `src/solo_miner.py` — Host-based solo miner (educational)
- `src/real_mining.py` — Educational examples and helper routines
- `src/test_pool_connection.py` — Pool connectivity testing utility

Quick start (Windows / PowerShell)

1) Install Python requirements (psutil is optional but recommended):- `src/real_mining.py` — Educational script that contains examples and helper routines. It now includes a `--host-solo` option which calls `solo_miner`.



## Quick setup (Windows / PowerShell)

The repository includes a `setup_env.ps1` helper that creates a virtual environment and installs dependencies.

**1. Create the environment (one-time):**

```powershell
.\setup_env.ps1
```

This installs all dependencies including:
- `flet[all]` — Desktop UI framework
- `psutil` — CPU monitoring and affinity control
- `requests` — HTTP client for pool API queries

**2. Launch the Flet Desktop UI:**

```powershell
uv run python -m src.main
```

The Flet desktop application will open with a modern interface for controlling the miner.

## UI Features

- **Modern Desktop Interface:** Built with Flet (Flutter-based Python framework)
- **Real-time Monitoring:** Auto-refreshing stats every 2 seconds
- **CPU Core Selection:** Visual checkboxes to select which cores to use for mining
- **Live CPU Usage:** See current usage percentage for each core
- **Configuration Profiles:** Save and load mining configurations
- **Pool Statistics:** View all workers connected to the pool
- **Status Display:** Current hashrate, uptime, shares found, and best difficulty

## Examples

**Run the simulated solo miner (no Bitcoin node required):**

```powershell
uv run .\src\solo_miner.py --max-nonce 50000 --procs 2
```

**Run solo miner using Bitcoin Core RPC (use regtest/testnet for testing):**

```powershell
uv run .\src\solo_miner.py --rpc-url http://127.0.0.1:18443 --rpc-user user --rpc-pass pass --max-nonce 100000 --procs 4
```

**Run the Stratum miner directly (dry-run by default):**

```powershell
uv run python -m src.backend.mining --host public-pool.io --port 21496 --worker bc1q... --procs 2
```

**To enable share submission (use only on testnet/regtest):**

```powershell
uv run python -m src.backend.mining --host public-pool.io --port 21496 --worker bc1q... --submit --procs 2
```

**Test pool connectivity:**

```powershell
uv run python src/test_pool_connection.py
# Or test specific pool:
uv run python src/test_pool_connection.py solo.ckpool.org 3333
```

## Core selection and affinity

- When you select cores in the UI and save the configuration, the miner receives `--cpus` parameter
- The miner sets CPU affinity for each worker process using `psutil`
- Affinity is applied per-worker using round-robin: `worker i -> cpu_list[i % len(cpu_list)]`
- If `psutil` is not installed or affinity cannot be set, the miner logs a warning and continues

## CLI usage (direct miner run)

Important flags for `src/backend/mining.py`:

- `--host` and `--port` — Pool address
- `--worker` — Worker string (BTC address or username.worker)
- `--procs` — Number of worker processes (default: CPU count - 1)
- `--cpus` — Comma-separated list of core indices for affinity (e.g., `0,1,2,3`)
- `--submit` — Enable share submission (disabled by default for safety)
- `--report-interval` — Seconds between status updates (default: 30)
- `--report-pool` — Query pool API for worker statistics
- `--status-port` — Serve status JSON on HTTP port (e.g., `4444`)
- `--serial-compat` — Use Arduino-style logging compatible with NerdMiner_v2

Example with all features:

```powershell
uv run python -m src.backend.mining --host public-pool.io --port 21496 --worker bc1q... --procs 4 --cpus 0,1,2,3 --submit --report-interval 5 --report-pool --status-port 4444 --serial-compat
```

## Safety & testing recommendations

## Safety & testing recommendations

- Prefer `regtest` or `testnet` for any flow that submits blocks or shares
- Running against mainnet is not recommended for experiments
- Do not expose Bitcoin RPC or Stratum endpoints to the public internet without proper security
- Never share private keys or wallet seeds with third parties
- CPU mining is not profitable on mainnet — this is for educational purposes only

## Where to look for logs and snapshots

- `src/backend/log/stratum.log` — Detailed miner logs (connections, jobs, shares)
- `src/backend/log/session_status.json` — Real-time mining statistics (read by UI)
- `src/backend/config/miner_configs.json` — Saved configuration profiles

## Mapping pool sessions

1. Enable `--report-pool` so the miner fetches pool worker info
2. In the UI, view **Pool workers** table to see all connected sessions
3. Match your worker by `auth_user` or worker name to find the `sessionId`
4. Check `stratum.log` for `Matched pool sessionId: <id>` entries
5. Use `uptime_seconds` and `est_hashrate_Hs` to correlate activity

## Troubleshooting

**Multiprocessing issues on Windows:**
- Fixed with `multiprocessing.freeze_support()` in `mining.py`
- Worker processes should spawn correctly now

**Pool connection timeout:**
- Use `test_pool_connection.py` to verify pool connectivity
- Check firewall/network settings
- Try known working pools: `solo.ckpool.org:3333` or `btc.viabtc.com:3333`

**CPU affinity not working:**
- Ensure `psutil` is installed: `pip install psutil`
- On Windows, may require Administrator privileges
- Check Task Manager to verify affinity is set

**UI not showing CPU cores:**
- Install `psutil`: `pip install psutil`
- Restart the application

## Architecture details

See `src/frontend/FRONTEND_README.md` for detailed documentation on:
- Separation of concerns (UI vs business logic)
- Controller pattern implementation
- Real-time update mechanism
- Configuration management

## Next steps / ideas

- Add hashrate history charts to the UI
- Implement dark mode support
- Add notification system for share acceptance
- Create mobile-responsive layout option
- Add support for multiple configuration profiles in UI
- Implement faster hashing backend (C extension, Cython)

## License

This project is educational/demo code. Use at your own risk.

---

**Happy mining! (educationally)** 🎓⛏️


