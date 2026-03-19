#!/usr/bin/env python3
"""dnsdump TUI — interaktive Textual-Oberfläche"""

from __future__ import annotations

import json
from typing import List, Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header,
    Input, Label, ProgressBar, RichLog, Static,
    TabbedContent, TabPane,
)

from dns_enum.resolver import resolve_all, reverse_lookup, DomainResult
from dns_enum.subdomains import enumerate_subdomains, load_wordlist, SubdomainHit
from dns_enum.zonetransfer import run_zone_transfers, ZoneTransferResult
from dns_enum.pathscan import scan_paths, load_path_wordlist, PathHit
from dns_enum.portscan import scan_ports, parse_port_list, PortHit, BUILTIN_PORT_LIST

# ------------------------------------------------------------------ #
# CSS                                                                  #
# ------------------------------------------------------------------ #

CSS = """
Screen {
    background: $background;
}

#form-panel {
    height: auto;
    background: $panel;
    padding: 1 2;
    border-bottom: tall $primary;
}

.form-row {
    height: 3;
    layout: horizontal;
    margin-bottom: 1;
}

.field-label {
    width: 14;
    content-align: right middle;
    padding-right: 1;
    color: $text-muted;
}

#domain-input {
    width: 1fr;
}

#ns-input {
    width: 1fr;
}

#wordlist-input {
    width: 1fr;
}

#path-wordlist-input {
    width: 1fr;
}

#ports-input {
    width: 1fr;
}

#threads-input {
    width: 8;
}

#scan-btn {
    margin-left: 2;
    min-width: 12;
}

#options-row {
    height: 3;
    layout: horizontal;
    margin-bottom: 0;
}

#options-row Checkbox {
    margin-right: 2;
    background: transparent;
}

#results-area {
    height: 1fr;
}

TabbedContent {
    height: 1fr;
}

TabPane {
    padding: 0;
}

DataTable {
    height: 1fr;
}

RichLog {
    height: 1fr;
    background: $background;
    padding: 0 1;
}

#status-bar {
    height: 3;
    background: $panel;
    border-top: tall $primary;
    layout: horizontal;
    padding: 0 2;
    content-align: left middle;
}

#status-label {
    width: 1fr;
    content-align: left middle;
}

#progress-container {
    width: 30;
    content-align: center middle;
}

ProgressBar {
    width: 28;
}

#export-btn {
    min-width: 16;
    margin-left: 2;
}

#export-btn.hidden {
    display: none;
}
"""

# ------------------------------------------------------------------ #
# App                                                                  #
# ------------------------------------------------------------------ #

class DnsDumpApp(App):
    TITLE = "dnsdump"
    SUB_TITLE = "DNS Reconnaissance"
    CSS = CSS

    BINDINGS = [
        Binding("ctrl+s", "scan",   "Scan",   show=True),
        Binding("ctrl+e", "export", "Export", show=True),
        Binding("ctrl+q", "quit",   "Quit",   show=True),
    ]

    # Stored results for export
    _dns_result:   Optional[DomainResult]       = None
    _subdomains:   List[SubdomainHit]           = []
    _zone_results: List[ZoneTransferResult]     = []
    _path_hits:    List[PathHit]               = []
    _port_hits:    List[PortHit]               = []

    # ── Layout ──────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()

        with Vertical(id="form-panel"):
            # Domain row
            with Horizontal(classes="form-row"):
                yield Label("Domain", classes="field-label")
                yield Input(placeholder="example.com", id="domain-input")
                yield Button("Scan", id="scan-btn", variant="primary")

            # Nameserver + Wordlist row
            with Horizontal(classes="form-row"):
                yield Label("Nameserver", classes="field-label")
                yield Input(placeholder="8.8.8.8  (optional)", id="ns-input")
                yield Label("Threads", classes="field-label")
                yield Input(value="50", id="threads-input")

            with Horizontal(classes="form-row"):
                yield Label("Wordlist", classes="field-label")
                yield Input(placeholder="Pfad zur Wordlist (leer = built-in)",
                            id="wordlist-input")

            with Horizontal(classes="form-row"):
                yield Label("Path WL", classes="field-label")
                yield Input(placeholder="Pfad zur Path-Wordlist (leer = built-in)",
                            id="path-wordlist-input")

            with Horizontal(classes="form-row"):
                yield Label("Ports", classes="field-label")
                yield Input(
                    placeholder=f"z.B. 22,80,443,8000-8100  (leer = {len(BUILTIN_PORT_LIST)} built-in)",
                    id="ports-input",
                )

            # Checkboxes
            with Horizontal(id="options-row"):
                yield Label("Optionen", classes="field-label")
                yield Checkbox("Subdomains", value=True,  id="cb-subdomains")
                yield Checkbox("AXFR",       value=True,  id="cb-axfr")
                yield Checkbox("Reverse DNS",value=False, id="cb-reverse")
                yield Checkbox("Path Scan",  value=False, id="cb-pathscan")
                yield Checkbox("Port Scan",  value=False, id="cb-portscan")

        with TabbedContent(id="results-area"):
            with TabPane("DNS Records", id="tab-dns"):
                yield DataTable(id="tbl-dns", cursor_type="row", zebra_stripes=True)
            with TabPane("Subdomains", id="tab-sub"):
                yield DataTable(id="tbl-sub", cursor_type="row", zebra_stripes=True)
            with TabPane("Zone Transfer", id="tab-axfr"):
                yield RichLog(id="log-axfr", highlight=True, markup=True)
            with TabPane("Reverse DNS", id="tab-rev"):
                yield RichLog(id="log-rev", highlight=True, markup=True)
            with TabPane("Path Scan", id="tab-paths"):
                yield DataTable(id="tbl-paths", cursor_type="row", zebra_stripes=True)
            with TabPane("Port Scan", id="tab-ports"):
                yield DataTable(id="tbl-ports", cursor_type="row", zebra_stripes=True)

        with Horizontal(id="status-bar"):
            yield Label("Bereit. Domain eingeben und Scan starten.",
                        id="status-label")
            with Vertical(id="progress-container"):
                yield ProgressBar(id="progress", show_eta=False, show_percentage=False)
            yield Button("Export JSON", id="export-btn",
                         variant="success", disabled=True)

        yield Footer()

    # ── On mount: setup tables ───────────────────────────────────────

    def on_mount(self) -> None:
        dns_tbl: DataTable = self.query_one("#tbl-dns")
        dns_tbl.add_columns("Type", "TTL", "Value", "Prio")

        sub_tbl: DataTable = self.query_one("#tbl-sub")
        sub_tbl.add_columns("Subdomain", "FQDN", "Adressen")

        path_tbl: DataTable = self.query_one("#tbl-paths")
        path_tbl.add_columns("Status", "Host", "Pfad", "URL")

        port_tbl: DataTable = self.query_one("#tbl-ports")
        port_tbl.add_columns("Host", "Port", "Service", "Banner")

    # ── Button / key handlers ────────────────────────────────────────

    @on(Button.Pressed, "#scan-btn")
    def handle_scan(self) -> None:
        self.action_scan()

    @on(Button.Pressed, "#export-btn")
    def handle_export(self) -> None:
        self.action_export()

    def action_scan(self) -> None:
        domain = self.query_one("#domain-input", Input).value.strip()
        if not domain:
            self._set_status("[red]Bitte Domain eingeben.[/red]")
            return
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break
        domain = domain.rstrip("/")
        self._clear_results()
        self._start_scan(domain)

    def action_export(self) -> None:
        domain = self.query_one("#domain-input", Input).value.strip()
        if not self._dns_result:
            return
        path = f"{domain}_dnsdump.json"
        data = {
            "domain": domain,
            "dns_records": [
                {"type": r.rtype, "value": r.value, "ttl": r.ttl,
                 "priority": r.priority}
                for r in self._dns_result.records
            ],
            "subdomains": [
                {"subdomain": h.subdomain, "fqdn": h.fqdn,
                 "addresses": h.addresses}
                for h in self._subdomains
            ],
            "zone_transfers": [
                {
                    "nameserver": z.nameserver,
                    "vulnerable": z.success,
                    "error": z.error,
                    "records": [
                        {"name": r.name, "type": r.rtype, "value": r.value}
                        for r in z.records
                    ],
                }
                for z in self._zone_results
            ],
            "path_scan": [
                {"host": h.host, "path": h.path,
                 "url": h.url, "status": h.status, "length": h.length}
                for h in self._path_hits
            ],
            "port_scan": [
                {"host": h.host, "port": h.port,
                 "service": h.service, "banner": h.banner}
                for h in self._port_hits
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self._set_status(f"[green]Exportiert nach {path}[/green]")

    # ── Helpers ──────────────────────────────────────────────────────

    def _clear_results(self) -> None:
        self.query_one("#tbl-dns",   DataTable).clear()
        self.query_one("#tbl-sub",   DataTable).clear()
        self.query_one("#tbl-paths", DataTable).clear()
        self.query_one("#tbl-ports", DataTable).clear()
        self.query_one("#log-axfr",  RichLog).clear()
        self.query_one("#log-rev",   RichLog).clear()
        self.query_one("#progress",  ProgressBar).update(total=100, progress=0)
        self.query_one("#export-btn", Button).disabled = True
        self._dns_result   = None
        self._subdomains   = []
        self._zone_results = []
        self._path_hits    = []
        self._port_hits    = []

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-label", Label).update(msg)

    def _get_opt(self, widget_id: str) -> bool:
        return self.query_one(widget_id, Checkbox).value

    def _get_threads(self) -> int:
        try:
            return int(self.query_one("#threads-input", Input).value)
        except ValueError:
            return 50

    # ── Worker ───────────────────────────────────────────────────────

    @work(thread=True, exclusive=True)
    def _start_scan(self, domain: str) -> None:
        ns       = self.query_one("#ns-input",       Input).value.strip() or None
        wordlist_path = self.query_one("#wordlist-input", Input).value.strip() or None
        threads  = self._get_threads()
        do_sub   = self._get_opt("#cb-subdomains")
        do_axfr  = self._get_opt("#cb-axfr")
        do_rev   = self._get_opt("#cb-reverse")

        # ── Phase 1: DNS Records ─────────────────────────────────────
        self.call_from_thread(self._set_status, "Abfrage DNS-Records…")
        result = resolve_all(domain, nameserver=ns)
        self._dns_result = result

        RTYPE_COLORS = {
            "A": "bright_green", "AAAA": "cyan", "MX": "yellow",
            "NS": "bright_blue", "TXT": "magenta", "CNAME": "bright_cyan",
            "SOA": "bright_yellow", "CAA": "orange1", "SRV": "bright_magenta",
        }
        order = ["SOA","NS","A","AAAA","CNAME","MX","TXT","CAA","SRV"]
        order_map = {r: i for i, r in enumerate(order)}
        sorted_recs = sorted(result.records,
                             key=lambda r: (order_map.get(r.rtype, 99), r.value))

        def add_dns_rows() -> None:
            tbl: DataTable = self.query_one("#tbl-dns")
            for rec in sorted_recs:
                color = RTYPE_COLORS.get(rec.rtype, "white")
                prio  = str(rec.priority) if rec.priority is not None else ""
                tbl.add_row(
                    f"[bold {color}]{rec.rtype}[/bold {color}]",
                    str(rec.ttl),
                    rec.value,
                    prio,
                )

        self.call_from_thread(add_dns_rows)
        self.call_from_thread(
            self._set_status,
            f"DNS Records: [bold]{len(result.records)}[/bold] gefunden"
        )

        # ── Phase 2: Zone Transfer ───────────────────────────────────
        if do_axfr:
            self.call_from_thread(self._set_status, "Versuche Zone Transfer (AXFR)…")
            zone_results = run_zone_transfers(domain)
            self._zone_results = zone_results

            def add_axfr_log() -> None:
                log: RichLog = self.query_one("#log-axfr")
                for z in zone_results:
                    if z.success:
                        log.write(f"[bold red]⚠  VULNERABLE[/bold red]  "
                                  f"NS [cyan]{z.nameserver}[/cyan] erlaubt Zone Transfer!")
                        for rec in z.records:
                            log.write(f"  [bright_cyan]{rec.name:<30}[/bright_cyan]  "
                                      f"[yellow]{rec.rtype:<8}[/yellow]  {rec.value}")
                    else:
                        log.write(f"[green]✓  OK[/green]  "
                                  f"[cyan]{z.nameserver}[/cyan]  "
                                  f"[dim]{z.error or 'verweigert'}[/dim]")

            self.call_from_thread(add_axfr_log)

        # ── Phase 3: Subdomains ──────────────────────────────────────
        if do_sub:
            wordlist = load_wordlist(wordlist_path)
            self.call_from_thread(
                self._set_status,
                f"Subdomain-Scan läuft… [dim](0 / {len(wordlist)})[/dim]"
            )
            self.call_from_thread(
                lambda: self.query_one("#progress", ProgressBar).update(
                    total=len(wordlist), progress=0
                )
            )

            done_count = [0]

            def on_progress(done: int, total: int) -> None:
                done_count[0] = done
                self.call_from_thread(
                    lambda d=done, t=total: (
                        self.query_one("#progress", ProgressBar).update(progress=d),
                        self._set_status(
                            f"Subdomain-Scan… [dim]{d} / {t}[/dim]"
                        )
                    )
                )

            def on_hit(hit: SubdomainHit) -> None:
                self.call_from_thread(
                    lambda h=hit: self.query_one("#tbl-sub", DataTable).add_row(
                        f"[bold bright_cyan]{h.subdomain}[/bold bright_cyan]",
                        h.fqdn,
                        ", ".join(h.addresses),
                    )
                )

            hits = enumerate_subdomains(
                domain=domain,
                wordlist=wordlist,
                threads=threads,
                nameserver=ns,
                progress_cb=on_progress,
                hit_cb=on_hit,
            )
            self._subdomains = hits
            self.call_from_thread(
                self._set_status,
                f"Subdomains: [bold]{len(hits)}[/bold] gefunden"
            )

        # ── Phase 4: Reverse DNS ─────────────────────────────────────
        if do_rev:
            ips: set[str] = set()
            if self._dns_result:
                for rec in self._dns_result.records:
                    if rec.rtype in ("A", "AAAA"):
                        ips.add(rec.value)
            for hit in self._subdomains:
                ips.update(hit.addresses)

            self.call_from_thread(self._set_status, "Reverse-DNS-Lookups…")

            def add_rev_log(ip_list: list[str]) -> None:
                log: RichLog = self.query_one("#log-rev")
                for ip in sorted(ip_list):
                    ptr = reverse_lookup(ip)
                    if ptr:
                        log.write(f"[cyan]{ip:<40}[/cyan] → [bright_green]{ptr}[/bright_green]")
                    else:
                        log.write(f"[cyan]{ip:<40}[/cyan] → [dim]kein PTR[/dim]")

            rev_list = list(ips)
            self.call_from_thread(add_rev_log, rev_list)

        # ── Phase 5: Path Scan ───────────────────────────────────────
        do_pathscan = self._get_opt("#cb-pathscan")
        if do_pathscan:
            path_wordlist_path = self.query_one("#path-wordlist-input", Input).value.strip() or None
            path_wordlist = load_path_wordlist(path_wordlist_path)

            hosts = [domain] + [hit.fqdn for hit in self._subdomains]
            total_tasks = len(hosts) * len(path_wordlist)

            self.call_from_thread(
                self._set_status,
                f"Path-Scan läuft… [dim](0 / {total_tasks})[/dim]"
            )
            self.call_from_thread(
                lambda t=total_tasks: self.query_one("#progress", ProgressBar).update(
                    total=t, progress=0
                )
            )

            def on_path_progress(done: int, total: int) -> None:
                self.call_from_thread(
                    lambda d=done, t=total: (
                        self.query_one("#progress", ProgressBar).update(progress=d),
                        self._set_status(f"Path-Scan… [dim]{d} / {t}[/dim]")
                    )
                )

            STATUS_COLORS = {
                200: "bright_green", 201: "bright_green", 204: "bright_green",
                301: "yellow", 302: "yellow", 307: "yellow", 308: "yellow",
                401: "orange1", 403: "bright_red", 500: "red",
            }

            def on_path_hit(hit: PathHit) -> None:
                color = STATUS_COLORS.get(hit.status, "white")
                self.call_from_thread(
                    lambda h=hit, c=color: self.query_one("#tbl-paths", DataTable).add_row(
                        f"[bold {c}]{h.status}[/bold {c}]",
                        h.host,
                        h.path,
                        h.url,
                    )
                )

            path_hits = scan_paths(
                hosts=hosts,
                wordlist=path_wordlist,
                threads=20,
                timeout=5,
                use_https=True,
                progress_cb=on_path_progress,
                hit_cb=on_path_hit,
            )
            self._path_hits = path_hits
            self.call_from_thread(
                self._set_status,
                f"Path-Scan: [bold]{len(path_hits)}[/bold] Treffer"
            )

        # ── Phase 6: Port Scan ───────────────────────────────────────
        do_portscan = self._get_opt("#cb-portscan")
        if do_portscan:
            raw_ports = self.query_one("#ports-input", Input).value.strip()
            ports = parse_port_list(raw_ports) if raw_ports else None

            hosts = [domain] + [hit.fqdn for hit in self._subdomains]
            port_list = ports or BUILTIN_PORT_LIST
            total_tasks = len(hosts) * len(port_list)

            self.call_from_thread(
                self._set_status,
                f"Port-Scan läuft… [dim](0 / {total_tasks})[/dim]"
            )
            self.call_from_thread(
                lambda t=total_tasks: self.query_one("#progress", ProgressBar).update(
                    total=t, progress=0
                )
            )

            def on_port_progress(done: int, total: int) -> None:
                self.call_from_thread(
                    lambda d=done, t=total: (
                        self.query_one("#progress", ProgressBar).update(progress=d),
                        self._set_status(f"Port-Scan… [dim]{d} / {t}[/dim]")
                    )
                )

            def on_port_hit(hit: PortHit) -> None:
                self.call_from_thread(
                    lambda h=hit: self.query_one("#tbl-ports", DataTable).add_row(
                        f"[bold bright_cyan]{h.host}[/bold bright_cyan]",
                        f"[bold bright_green]{h.port}[/bold bright_green]",
                        f"[yellow]{h.service}[/yellow]",
                        f"[dim]{h.banner}[/dim]" if h.banner else "",
                    )
                )

            port_hits = scan_ports(
                hosts=hosts,
                ports=ports,
                threads=100,
                timeout=1.5,
                progress_cb=on_port_progress,
                hit_cb=on_port_hit,
            )
            self._port_hits = port_hits
            self.call_from_thread(
                self._set_status,
                f"Port-Scan: [bold]{len(port_hits)}[/bold] offene Ports"
            )

        # ── Fertig ───────────────────────────────────────────────────
        total_records = len(self._dns_result.records) if self._dns_result else 0
        total_subs    = len(self._subdomains)
        vuln          = sum(1 for z in self._zone_results if z.success)

        summary = (
            f"Fertig — Records: [bold]{total_records}[/bold]  "
            f"Subdomains: [bold]{total_subs}[/bold]"
        )
        if self._zone_results:
            color = "bright_red" if vuln else "green"
            summary += f"  AXFR: [{color}]{vuln} vulnerable[/{color}]"
        if self._path_hits:
            summary += f"  Paths: [bold bright_yellow]{len(self._path_hits)}[/bold bright_yellow] gefunden"
        if self._port_hits:
            summary += f"  Ports: [bold bright_cyan]{len(self._port_hits)}[/bold bright_cyan] offen"

        self.call_from_thread(self._set_status, summary)
        self.call_from_thread(
            lambda: setattr(
                self.query_one("#export-btn", Button), "disabled", False
            )
        )


# ------------------------------------------------------------------ #

if __name__ == "__main__":
    DnsDumpApp().run()
