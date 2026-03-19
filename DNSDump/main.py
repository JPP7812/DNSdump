#!/usr/bin/env python3
"""
dnsdump — DNS reconnaissance tool inspired by DNS Dumpster
Usage: python main.py <domain> [options]
"""

import argparse
import sys
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from dns_enum.resolver import resolve_all, reverse_lookup
from dns_enum.subdomains import enumerate_subdomains, load_wordlist
from dns_enum.zonetransfer import run_zone_transfers
from dns_enum import report

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dnsdump",
        description="DNS reconnaissance — enumerate records, subdomains, zone transfers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --subdomains --wordlist /usr/share/wordlists/subdomains.txt
  python main.py example.com --no-axfr --threads 100 --output results.json
  python main.py example.com --reverse
  python main.py example.com --nameserver 8.8.8.8
        """,
    )
    p.add_argument("domain",
                   help="Target domain (e.g. example.com)")
    p.add_argument("-s", "--subdomains", action="store_true", default=True,
                   help="Enumerate subdomains (default: on)")
    p.add_argument("--no-subdomains", dest="subdomains", action="store_false",
                   help="Skip subdomain enumeration")
    p.add_argument("-w", "--wordlist", metavar="FILE",
                   help="Custom subdomain wordlist (one per line)")
    p.add_argument("-t", "--threads", type=int, default=50,
                   help="Threads for subdomain enumeration (default: 50)")
    p.add_argument("--no-axfr", action="store_true",
                   help="Skip zone transfer attempts")
    p.add_argument("-r", "--reverse", action="store_true",
                   help="Reverse-lookup all discovered A/AAAA addresses")
    p.add_argument("-n", "--nameserver", metavar="IP",
                   help="Use custom nameserver (default: system resolver)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Save results as JSON to FILE")
    p.add_argument("--version", action="version", version="dnsdump 1.0.0")
    return p.parse_args()


def collect_ips(dns_result, subdomain_hits) -> list[str]:
    ips = set()
    for rec in dns_result.records:
        if rec.rtype in ("A", "AAAA"):
            ips.add(rec.value)
    for hit in subdomain_hits:
        ips.update(hit.addresses)
    return sorted(ips)


def main() -> None:
    args = parse_args()
    domain = args.domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break
    domain = domain.rstrip("/")

    report.print_banner(domain)

    # ── 1. DNS Records ──────────────────────────────────────────────
    with console.status("[bold cyan]Querying DNS records…[/bold cyan]"):
        dns_result = resolve_all(domain, nameserver=args.nameserver)

    report.print_dns_records(dns_result)

    # ── 2. Zone Transfer ────────────────────────────────────────────
    zone_results = []
    if not args.no_axfr:
        with console.status("[bold cyan]Attempting zone transfers…[/bold cyan]"):
            zone_results = run_zone_transfers(domain)
        report.print_zone_transfers(zone_results)

    # ── 3. Subdomain Enumeration ────────────────────────────────────
    subdomain_hits = []
    if args.subdomains:
        wordlist = load_wordlist(args.wordlist)
        console.rule(f"[bold]Subdomain Enumeration[/bold]  "
                     f"[dim]({len(wordlist)} words, {args.threads} threads)[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning…", total=len(wordlist))

            def on_progress(done: int, total: int) -> None:
                progress.update(task, completed=done)

            subdomain_hits = enumerate_subdomains(
                domain=domain,
                wordlist=wordlist,
                threads=args.threads,
                nameserver=args.nameserver,
                progress_cb=on_progress,
            )

        report.print_subdomains(subdomain_hits, domain)

    # ── 4. Reverse Lookups ──────────────────────────────────────────
    if args.reverse:
        all_ips = collect_ips(dns_result, subdomain_hits)
        if all_ips:
            console.rule("[bold]Reverse DNS Lookups[/bold]")
            for ip in all_ips:
                ptr = reverse_lookup(ip)
                report.print_reverse(ip, ptr)
            console.print()

    # ── 5. Summary ──────────────────────────────────────────────────
    console.rule("[bold]Summary[/bold]")
    console.print(f"  DNS records    : [bold]{len(dns_result.records)}[/bold]")
    console.print(f"  Subdomains     : [bold]{len(subdomain_hits)}[/bold]")

    if zone_results:
        vuln = sum(1 for z in zone_results if z.success)
        color = "bright_red" if vuln else "green"
        console.print(f"  Zone transfers : [{color}]{vuln} vulnerable / "
                      f"{len(zone_results)} tested[/{color}]")

    # ── 6. Export ───────────────────────────────────────────────────
    if args.output:
        report.export_json(domain, dns_result, subdomain_hits,
                           zone_results, args.output)

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Aborted.[/dim]")
        sys.exit(0)
