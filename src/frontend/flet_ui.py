"""
Flet UI for Bitcoin Mining Concept.
Modern desktop/web UI using Flet framework.
"""
import threading
import time

import flet as ft

from src.backend.mining_controller import MiningController


class MiningApp:
    """Main Flet application for Bitcoin mining control."""

    def __init__(self, page: ft.Page):
        self.page = page
        self.controller = MiningController()
        self.update_timer = None

        # Configure page
        self.page.title = "Bitcoin Mining Concept"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 20

        # UI Components (will be created in build_ui)
        self.status_text = None
        self.hashrate_text = None
        self.uptime_text = None
        self.worker_text = None
        self.start_button = None
        self.stop_button = None
        self.address_field = None
        self.port_field = None
        self.btc_address_field = None
        self.cpu_checkboxes = []
        self.cpu_container = None
        self.pool_workers_table = None

        # Build and show UI
        self.build_ui()
        self.page.update()

        # Load saved config
        self.load_config()

        # Start update loop
        self.start_updates()

    def build_ui(self):
        """Build the Flet UI components."""

        # Header
        header = ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.CURRENCY_BITCOIN,
                        size=40, color=ft.Colors.ORANGE),
                ft.Text("Bitcoin Mining Concept", size=28,
                        weight=ft.FontWeight.BOLD),
            ]),
            padding=ft.padding.only(bottom=20)
        )

        # Configuration Section
        self.address_field = ft.TextField(
            label="Pool Address",
            value="public-pool.io",
            width=300
        )

        self.port_field = ft.TextField(
            label="Port",
            value="21496",
            width=150
        )

        self.btc_address_field = ft.TextField(
            label="BTC Address / Worker",
            value="bc1qug6j3j2et4q02padn85edu7xlk0scrf8ue2h9d",
            width=500
        )

        save_config_btn = ft.ElevatedButton(
            "Save Configuration",
            icon=ft.Icons.SAVE,
            on_click=self.on_save_config
        )

        config_section = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Mining Configuration", size=20,
                            weight=ft.FontWeight.BOLD),
                    ft.Row([self.address_field, self.port_field]),
                    self.btc_address_field,
                    save_config_btn,
                ]),
                padding=15
            )
        )

        # Control Section
        self.start_button = ft.ElevatedButton(
            "Start Mining",
            icon=ft.Icons.PLAY_ARROW,
            on_click=self.on_start_mining,
            color=ft.Colors.WHITE,
            bgcolor=ft.Colors.GREEN
        )

        self.stop_button = ft.ElevatedButton(
            "Stop Mining",
            icon=ft.Icons.STOP,
            on_click=self.on_stop_mining,
            color=ft.Colors.WHITE,
            bgcolor=ft.Colors.RED,
            visible=False
        )

        control_section = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Controls", size=20, weight=ft.FontWeight.BOLD),
                    ft.Row([self.start_button, self.stop_button]),
                ]),
                padding=15
            )
        )

        # CPU Cores Section
        self.cpu_container = ft.Column()

        cpu_section = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text("CPU Cores", size=20, weight=ft.FontWeight.BOLD),
                    self.cpu_container,
                ]),
                padding=15
            )
        )

        # Status Section
        self.status_text = ft.Text(
            "Status: Stopped", size=16, weight=ft.FontWeight.BOLD)
        self.hashrate_text = ft.Text("Hashrate: 0 H/s")
        self.uptime_text = ft.Text("Uptime: 0s")
        self.worker_text = ft.Text("Worker: -")

        status_section = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Mining Status", size=20,
                            weight=ft.FontWeight.BOLD),
                    self.status_text,
                    self.hashrate_text,
                    self.uptime_text,
                    self.worker_text,
                ]),
                padding=15
            )
        )

        # Pool Workers Section
        self.pool_workers_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("Session ID")),
                ft.DataColumn(ft.Text("Name")),
                ft.DataColumn(ft.Text("Hashrate")),
                ft.DataColumn(ft.Text("Last Seen")),
            ],
            rows=[]
        )

        pool_section = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Pool Workers", size=20,
                            weight=ft.FontWeight.BOLD),
                    ft.Container(
                        content=self.pool_workers_table,
                        height=300,
                    )
                ]),
                padding=15
            )
        )

        # Layout
        left_column = ft.Column([
            config_section,
            control_section,
            cpu_section,
        ], width=600, scroll=ft.ScrollMode.AUTO)

        right_column = ft.Column([
            status_section,
            pool_section,
        ], expand=True, scroll=ft.ScrollMode.AUTO)

        main_layout = ft.Row([
            left_column,
            right_column,
        ], expand=True, spacing=20)

        # Add to page
        self.page.add(header, main_layout)

    def load_config(self):
        """Load saved configuration into UI."""
        try:
            configs = self.controller.load_configs()
            if configs:
                # Get first config
                first_config = configs[next(iter(configs))]

                if 'address' in first_config:
                    self.address_field.value = first_config['address']
                if 'port' in first_config:
                    self.port_field.value = str(first_config['port'])
                if 'btc_address' in first_config:
                    self.btc_address_field.value = first_config['btc_address']

                self.page.update()
        except Exception as e:
            print(f"Failed to load config: {e}")

    def on_start_mining(self, e):  # noqa: ARG002
        """Handle start mining button click."""
        config = {
            'address': self.address_field.value,
            'port': self.port_field.value,
            'btc_address': self.btc_address_field.value,
            'submit': True,
            'report_pool': True,
            'report_interval': 5,
        }

        # Get selected cores
        selected_cores = [i for i, cb in enumerate(
            self.cpu_checkboxes) if cb.value]
        if selected_cores:
            config['core'] = selected_cores

        success, msg = self.controller.start_miner(config)

        if success:
            self.start_button.visible = False
            self.stop_button.visible = True
            self.status_text.value = "Status: Running"
            self.status_text.color = ft.Colors.GREEN
        else:
            self.show_snackbar(f"Failed to start: {msg}", error=True)

        self.page.update()

    def on_stop_mining(self, e):  # noqa: ARG002
        """Handle stop mining button click."""
        success, msg = self.controller.stop_miner()

        if success:
            self.start_button.visible = True
            self.stop_button.visible = False
            self.status_text.value = "Status: Stopped"
            self.status_text.color = None
        else:
            self.show_snackbar(f"Failed to stop: {msg}", error=True)

        self.page.update()

    def on_save_config(self, e):  # noqa: ARG002
        """Handle save configuration button click."""
        config = {
            'address': self.address_field.value,
            'port': self.port_field.value,
            'btc_address': self.btc_address_field.value,
            'submit': True,
            'report_pool': True,
            'report_interval': 5,
        }

        # Get selected cores
        selected_cores = [i for i, cb in enumerate(
            self.cpu_checkboxes) if cb.value]
        if selected_cores:
            config['core'] = selected_cores

        name = config['btc_address'] or 'default'
        success = self.controller.save_config(name, config)

        if success:
            self.show_snackbar("Configuration saved successfully")
        else:
            self.show_snackbar("Failed to save configuration", error=True)

    def on_core_toggle(self, e):  # noqa: ARG002
        """Handle CPU core checkbox toggle."""
        selected_cores = [i for i, cb in enumerate(
            self.cpu_checkboxes) if cb.value]
        result = self.controller.update_cpu_cores(selected_cores)

        if result.get('ok'):
            self.show_snackbar(f"Updated cores: {selected_cores}")
        else:
            self.show_snackbar("Failed to update cores", error=True)

    def update_status(self):
        """Update status display from controller."""
        try:
            status = self.controller.get_status()

            # Update running state
            if status.get('running'):
                if self.start_button.visible:
                    self.start_button.visible = False
                    self.stop_button.visible = True
                    self.status_text.value = "Status: Running"
                    self.status_text.color = ft.Colors.GREEN
            else:
                if self.stop_button.visible:
                    self.start_button.visible = True
                    self.stop_button.visible = False
                    self.status_text.value = "Status: Stopped"
                    self.status_text.color = None

            # Update metrics
            hashrate = status.get(
                'hashRate_human') or f"{status.get('est_hashrate_Hs', 0):.2f} H/s"
            self.hashrate_text.value = f"Hashrate: {hashrate}"

            uptime = status.get('uptime_seconds', 0)
            self.uptime_text.value = f"Uptime: {int(uptime)}s"

            worker = status.get('worker') or status.get('auth_user') or '-'
            self.worker_text.value = f"Worker: {worker}"

            # Update pool workers table
            pool = status.get('pool', {})
            workers = pool.get('workers', []) if isinstance(pool, dict) else []

            self.pool_workers_table.rows.clear()
            for w in workers[:10]:  # Limit to 10 workers
                self.pool_workers_table.rows.append(
                    ft.DataRow(cells=[
                        ft.DataCell(ft.Text(w.get('sessionId', '')[:8])),
                        ft.DataCell(ft.Text(w.get('name', ''))),
                        ft.DataCell(
                            ft.Text(f"{float(w.get('hashRate', 0)):.2f}")),
                        ft.DataCell(ft.Text(w.get('lastSeen', '')[-8:])),
                    ])
                )

            self.page.update()
        except Exception as e:
            print(f"Failed to update status: {e}")

    def update_cpu_cores(self):
        """Update CPU cores display."""
        try:
            cores = self.controller.get_cpu_cores()

            # Rebuild checkboxes if count changed
            if len(cores) != len(self.cpu_checkboxes):
                self.cpu_checkboxes.clear()
                self.cpu_container.controls.clear()

                rows = []
                current_row = []

                for core in cores:
                    cb = ft.Checkbox(
                        label=f"Core {core['id']}: {core['percent']:.1f}%",
                        value=core['selected'],
                        on_change=self.on_core_toggle
                    )
                    self.cpu_checkboxes.append(cb)
                    current_row.append(cb)

                    if len(current_row) == 4:
                        rows.append(ft.Row(current_row))
                        current_row = []

                if current_row:
                    rows.append(ft.Row(current_row))

                self.cpu_container.controls = rows
            else:
                # Just update percentages
                for i, core in enumerate(cores):
                    if i < len(self.cpu_checkboxes):
                        self.cpu_checkboxes[i].label = f"Core {core['id']}: {core['percent']:.1f}%"

            self.page.update()
        except Exception as e:
            print(f"Failed to update CPU cores: {e}")

    def start_updates(self):
        """Start background update thread."""
        def update_loop():
            while True:
                try:
                    self.update_status()
                    self.update_cpu_cores()
                except Exception as e:
                    print(f"Update loop error: {e}")
                time.sleep(2)

        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()

    def show_snackbar(self, message: str, error: bool = False):
        """Show a snackbar notification."""
        snack = ft.SnackBar(
            content=ft.Text(message),
            bgcolor=ft.Colors.RED if error else ft.Colors.GREEN
        )
        self.page.snack_bar = snack
        snack.open = True
        self.page.update()


def main(page: ft.Page):
    """Main entry point for Flet app."""
    MiningApp(page)


if __name__ == "__main__":
    ft.app(target=main)
