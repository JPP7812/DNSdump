"""Rich-formatted output for DNS enumeration results."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import json
from typing import List

from .resolver import DomainResult, DnsRecord
from .subdomains import SubdomainHit
from .zonetransfer import ZoneTransferResult

console = Console()

# Color per record type
RTYPE_COLORS = {
    "A":     "bright_green",
    "AAAA":  "cyan",
    "MX":    "yellow",
    "NS":    "bright_blue",
    "TXT":   "magenta",
    "CNAME": "bright_cyan",
    "SOA":   "bright_yellow",
    "CAA":   "orange1",
    "SRV":   "bright_magenta",
    "PTR":   "green",
}


def _rtype_styled(rtype: str) -> Text:
    color = RTYPE_COLORS.get(rtype, "white")
    return Text(rtype, style=f"bold {color}")


# ------------------------------------------------------------------ #

def print_banner(domain: str) -> None:
    console.print(Panel(
        f"[bold bright_cyan]DNS Dumpster[/bold bright_cyan]  "
        f"[dim]–[/dim]  [bold white]{domain}[/bold white]",
        subtitle="[dim]authorized recon only[/dim]",
        box=box.DOUBLE_EDGE,
        expand=False,
    ))
    console.print()


def print_dns_records(result: DomainResult) -> None:
    if not result.records:
        console.print("[dim]No DNS records found.[/dim]\n")
        return

    table = Table(
        title=f"DNS Records — {result.domain}",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=False,
    )
    table.add_column("Type",  style="bold", width=8)
    table.add_column("TTL",   style="dim",  width=8)
    table.add_column("Value", overflow="fold")
    table.add_column("Prio",  style="dim",  width=6)

    # Group by type for readability
    order = ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"]
    rtype_order = {r: i for i, r in enumerate(order)}
    sorted_records = sorted(
        result.records,
        key=lambda r: (rtype_order.get(r.rtype, 99), r.value)
    )

    for rec in sorted_records:
        prio = str(rec.priority) if rec.priority is not None else ""
        table.add_row(
            _rtype_styled(rec.rtype),
            str(rec.ttl),
            rec.value,
            prio,
        )

    console.print(table)
    console.print()


def print_subdomains(hits: List[SubdomainHit], domain: str) -> None:
    console.rule(f"[bold]Subdomains — {domain}[/bold]")
    if not hits:
        console.print("[dim]  No subdomains found.[/dim]\n")
        return

    table = Table(box=box.SIMPLE, show_header=True, expand=False)
    table.add_column("Subdomain",  style="bold bright_cyan", min_width=25)
    table.add_column("FQDN",       style="dim")
    table.add_column("Addresses",  style="bright_green")

    for hit in hits:
        table.add_row(hit.subdomain, hit.fqdn, ", ".join(hit.addresses))

    console.print(table)
    console.print(f"  [bold]{len(hits)}[/bold] subdomain(s) found\n")


def print_zone_transfers(results: List[ZoneTransferResult]) -> None:
    console.rule("[bold]Zone Transfer (AXFR)[/bold]")
    for r in results:
        if r.success:
            console.print(
                f"  [bold bright_red]VULNERABLE[/bold bright_red]  "
                f"NS [cyan]{r.nameserver}[/cyan] allows zone transfer!"
            )
            table = Table(box=box.MINIMAL, show_header=True, expand=False)
            table.add_column("Name",  style="bright_cyan")
            table.add_column("Type",  style="bold yellow")
            table.add_column("Value", overflow="fold")
            for rec in r.records:
                table.add_row(rec.name, rec.rtype, rec.value)
            console.print(table)
        else:
            console.print(
                f"  [green]OK[/green]  NS [cyan]{r.nameserver}[/cyan]"
                f"  [dim]{r.error or 'refused'}[/dim]"
            )
    console.print()


def print_reverse(ip: str, hostname: str | None) -> None:
    if hostname:
        console.print(f"  [cyan]{ip}[/cyan]  →  [bright_green]{hostname}[/bright_green]")
    else:
        console.print(f"  [cyan]{ip}[/cyan]  →  [dim]no PTR record[/dim]")


# ------------------------------------------------------------------ #
# JSON / text export                                                   #
# ------------------------------------------------------------------ #

def export_json(
    domain: str,
    dns_result: DomainResult,
    subdomains: List[SubdomainHit],
    zone_results: List[ZoneTransferResult],
    path: str,
) -> None:
    data = {
        "domain": domain,
        "dns_records": [
            {"type": r.rtype, "value": r.value, "ttl": r.ttl,
             "priority": r.priority}
            for r in dns_result.records
        ],
        "subdomains": [
            {"subdomain": h.subdomain, "fqdn": h.fqdn,
             "addresses": h.addresses}
            for h in subdomains
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
            for z in zone_results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"\n[dim]Results saved to[/dim] [bold]{path}[/bold]")
