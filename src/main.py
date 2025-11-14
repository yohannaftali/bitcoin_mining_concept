"""Entry point to start the Flet UI for Bitcoin Mining.

Usage:
    uv run ./src/main.py
    python -m src.main

This module starts the Flet desktop application for controlling
the Bitcoin miner.
"""
import flet as ft
from src.frontend.flet_ui import main as flet_main


def main():
    """Launch the Flet desktop application."""
    ft.app(target=flet_main)


if __name__ == '__main__':
    main()
