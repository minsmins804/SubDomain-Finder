#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import sys

from dns_fingerprint import dns_fingerprint
from port_scanner import scan_ports
from webserver_fingerprint import detect_webserver
from cloud_detector import detect_cloud



from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, BarColumn, TextColumn
from rich.table import Table

from subdomainfinder.brute_force import BruteForceScanner
from subdomainfinder.enums import OutputFormat
from subdomainfinder.services import ServiceScanner
from subdomainfinder.utils import setup_logging, save_results, clean_and_deduplicate_subdomains

console = Console()


# ----------------------------
# ARGUMENT PARSER (fixed)
# ----------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SubDomain-Finder - A high-performance subdomain discovery tool'
    )

    parser.add_argument("--bruteforce", action="store_true",
                        help="Enable external brute-force module")

    parser.add_argument("--deep", action="store_true",
                        help="Enable level-2 deep brute-force")

    parser.add_argument('-d', '--domain', required=True,
                        help='Target domain to scan')

    parser.add_argument('-w', '--wordlist',
                        default='wordlists/default.txt',
                        help='Path to wordlist for brute-force (default: wordlists/default.txt)')

    parser.add_argument('-o', '--output', help='Output file path')

    parser.add_argument('-f', '--format',
                        choices=['text', 'json'],
                        default='json',
                        help='Output format (text/json)')

    parser.add_argument('-t', '--threads', type=int,
                        default=10,
                        help='Number of concurrent threads (default: 10)')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    return parser.parse_args()


# ---------------------------------------------------------
# UI TABLE FORMATTING
# ---------------------------------------------------------
def display_results(subdomains, source):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("No.", style="dim", width=6)
    table.add_column("Subdomain", style="green")
    table.add_column("Source", style="cyan")

    for idx, subdomain in enumerate(sorted(subdomains), 1):
        table.add_row(str(idx), subdomain, source)

    return table



# --------------------------
# Output helper
# --------------------------
def make_default_output(domain: str, fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = domain.replace("/", "_").replace("\\", "_")
    return f"results_{safe}_{ts}.{ 'json' if fmt=='json' else 'txt'}"


def ensure_extension(path: str, fmt: str) -> str:
    p = Path(path)

    if str(path).endswith(os.path.sep) or p.is_dir():
        return str(Path(path) / make_default_output("output", fmt))

    if fmt == "json" and p.suffix != ".json":
        return str(p.with_suffix(".json"))

    if fmt == "text" and p.suffix not in (".txt", ".csv"):
        return str(p.with_suffix(".txt"))

    return str(p)


# ======================================================
#                        MAIN
# ======================================================
async def main():
    args = parse_arguments()
    logger = setup_logging(args.verbose)

    # ---------------------------
    # EXTERNAL BRUTE FORCE MODULE
    # ---------------------------
    ext_results = set()

    if args.bruteforce:
        from external_bruteforce import brute_force, brute_force_deep

        console.print("[cyan]Running external brute-force...[/cyan]")

        if args.deep:
            ext_results = set(brute_force_deep(args.domain, args.wordlist))
        else:
            ext_results = set(brute_force(args.domain, args.wordlist))

        console.print(f"[green]External BF found {len(ext_results)} subdomains[/green]")

        with open("bruteforce_results.json", "w") as fp:
            json.dump(list(ext_results), fp, indent=4)

        console.print("[green]Saved to bruteforce_results.json[/green]")

    # -------------------------
    # CORE MODULES
    # -------------------------
    if not os.path.exists(args.wordlist):
        console.print(f"[red]Error: Wordlist '{args.wordlist}' not found[/red]")
        sys.exit(1)

    output_path = ensure_extension(args.output if args.output else "output", args.format)

    brute_scanner = BruteForceScanner(args.domain, args.wordlist, args.threads)
    service_scanner = ServiceScanner(args.domain)

    core_bruteforce = set()
    core_services = set()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )

    with progress:
        t1 = progress.add_task("[cyan]Core brute-force running...", total=None)
        core_bruteforce = await brute_scanner.scan()
        progress.update(t1, completed=True)

        t2 = progress.add_task("[cyan]Scanning services...", total=None)
        core_services = await service_scanner.scan()
        progress.update(t2, completed=True)

    final = set()

    if ext_results:
        cleaned = clean_and_deduplicate_subdomains(ext_results, args.domain)
        console.print("\n[bold cyan]External Brute Force:[/bold cyan]")
        console.print(display_results(cleaned, "External BF"))
        final.update(cleaned)

    if core_bruteforce:
        cleaned = clean_and_deduplicate_subdomains(core_bruteforce, args.domain)
        console.print("\n[bold cyan]Core Brute Force:[/bold cyan]")
        console.print(display_results(cleaned, "Core BF"))
        final.update(cleaned)

    if core_services:
        cleaned = clean_and_deduplicate_subdomains(core_services, args.domain)
        console.print("\n[bold cyan]Services:[/bold cyan]")
        console.print(display_results(cleaned, "Services"))
        final.update(cleaned)

    # ----------------------
    # SAVE OUTPUT
    # ----------------------
    final = sorted(final)
    # DNS Fingerprint Analysis
    console.print("\n[bold cyan]DNS Fingerprint Analysis[/bold cyan]")

    dns_table = Table(show_header=True, header_style="bold yellow")
    dns_table.add_column("Subdomain", style="green")
    dns_table.add_column("CNAME", style="cyan")
    dns_table.add_column("MX", style="magenta")
    dns_table.add_column("TXT", style="white")

    for s in final:
        info = dns_fingerprint(s)
        dns_table.add_row(
            s,
            info["cname"] if info["cname"] else "-",
            ", ".join(info["mx"]) if info["mx"] else "-",
            str(len(info["txt"]))
        )

    console.print(dns_table)
    #SCAN Port
    console.print("\n[bold green]Port Scan Results[/bold green]")

    port_table = Table(show_header=True, header_style="bold green")
    port_table.add_column("Subdomain", style="cyan")
    port_table.add_column("80", style="white")
    port_table.add_column("443", style="white")
    port_table.add_column("8080", style="white")
    port_table.add_column("8443", style="white")

    for s in final:
        ports = scan_ports(s)
        port_table.add_row(
            s,
            ports[80],
            ports[443],
            ports[8080],
            ports[8443]
        )

    console.print(port_table)
    
#webserver_finger
    console.print("\n[bold magenta]Web Server Fingerprint[/bold magenta]")

    ws_table = Table(show_header=True, header_style="bold magenta")
    ws_table.add_column("Subdomain", style="cyan")
    ws_table.add_column("Web Server", style="white")
    ws_table.add_column("CDN", style="yellow")

    for s in final:
        ws = detect_webserver(s)
        ws_table.add_row(
            s,
            ws["server"],
            ws["cdn"]
        )

    console.print(ws_table)
    #Cloud Provider
    console.print("\n[bold blue]Cloud Provider Detection[/bold blue]")

    cloud_table = Table(show_header=True, header_style="bold blue")
    cloud_table.add_column("Subdomain", style="cyan")
    cloud_table.add_column("Provider", style="magenta")
    cloud_table.add_column("CNAME", style="yellow")
    cloud_table.add_column("IP", style="white")

    for s in final:
        info = detect_cloud(s)
        cloud_table.add_row(
            s,
            info["provider"],
            info["cname"],
            info["ip"]
        )

    console.print(cloud_table)



# SAVE FINAL RESULTS

    if final:
        fmt = OutputFormat.JSON if args.format == "json" else OutputFormat.TEXT
        save_results(final, output_path, fmt)
        console.print(f"[green]Saved final results to {output_path}[/green]")
    else:
        console.print("[yellow]No subdomains found.[/yellow]")


if __name__ == "__main__":
    asyncio.run(main())
