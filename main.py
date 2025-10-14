#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import sys
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

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SubDomain-Finder - A high-performance subdomain discovery tool'
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument(
        '-w',
        '--wordlist',
        default='wordlists/default.txt',
        help='Path to wordlist for brute-force (default: wordlists/default.txt)'
    )
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument(
        '-f',
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (text/json) (default: text)'
    )
    parser.add_argument(
        '-t',
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def display_results(subdomains, source):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("No.", style="dim", width=6)
    table.add_column("Subdomain", style="green")
    table.add_column("Source", style="cyan")

    for idx, subdomain in enumerate(sorted(subdomains), 1):
        table.add_row(f"{idx}", subdomain, source)

    return table

def make_default_output(domain: str, fmt: str) -> str:
    """
    Create a timestamped default filename for output.
    fmt: 'json' or 'text'
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    if fmt == "json":
        return f"results_{safe_domain}_{ts}.json"
    else:
        return f"results_{safe_domain}_{ts}.txt"

def ensure_extension(path: str, fmt: str) -> str:
    """
    Ensure path ends with .json for json format or .txt for text.
    If user passed a directory, create a filename inside it.
    """
    p = Path(path)
    # if it's a directory (ends with path sep or is an existing dir), place file inside it
    if str(path).endswith(os.path.sep) or p.is_dir():
        return str(Path(path) / make_default_output("output", fmt))

    suffix = p.suffix.lower()
    if fmt == "json":
        if suffix != ".json":
            return str(p.with_suffix(".json"))
    else:
        if suffix not in (".txt", ".csv"):
            return str(p.with_suffix(".txt"))
    return str(p)

async def main():
    args = parse_arguments()
    logger = setup_logging(args.verbose)

    if not os.path.exists(args.wordlist):
        console.print(f"[red]Error: Wordlist file '{args.wordlist}' not found[/red]")
        sys.exit(1)

    try:
        # Decide output filename (timestamped if not provided)
        if args.output:
            out_path = ensure_extension(args.output, args.format)
        else:
            out_path = make_default_output(args.domain, args.format)

        # Initialize scanners
        brute_force = BruteForceScanner(args.domain, args.wordlist, args.threads)
        service_scanner = ServiceScanner(args.domain)

        subdomains_from_brute = set()
        subdomains_from_services = set()

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn()
        )

        with progress:
            # Run brute force scanning
            task1 = progress.add_task("[cyan]Running brute force scan...", total=None)
            subdomains_from_brute = await brute_force.scan()
            progress.update(task1, completed=True)

            # Run service scanning
            task2 = progress.add_task("[cyan]Scanning third-party services...", total=None)
            subdomains_from_services = await service_scanner.scan()
            progress.update(task2, completed=True)

        # Clean and combine results
        all_subdomains = set()

        # Process and display brute force results
        if subdomains_from_brute:
            clean_brute = clean_and_deduplicate_subdomains(subdomains_from_brute, args.domain)
            if clean_brute:
                console.print("\n[bold cyan]Results from Brute Force:[/bold cyan]")
                console.print(display_results(clean_brute, "Brute Force"))
                all_subdomains.update(clean_brute)

        # Process and display service results
        if subdomains_from_services:
            clean_services = clean_and_deduplicate_subdomains(subdomains_from_services, args.domain)
            if clean_services:
                console.print("\n[bold cyan]Results from Services:[/bold cyan]")
                console.print(display_results(clean_services, "Services"))
                all_subdomains.update(clean_services)

        # Save or display final results
        if all_subdomains:
            final_results = sorted(all_subdomains)
            console.print(f"\n[bold green]Total unique subdomains found: {len(final_results)}[/bold green]")

            output_format = OutputFormat.JSON if args.format == 'json' else OutputFormat.TEXT
            # ensure parent dir exists
            out_parent = Path(out_path).parent
            if not out_parent.exists():
                out_parent.mkdir(parents=True, exist_ok=True)

            save_results(final_results, out_path, output_format)
            console.print(f"[green]Results saved to '{out_path}'[/green]")
        else:
            console.print("[yellow]No valid subdomains found.[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.exception("An error occurred during scanning")
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    console.print("[bold blue]SubDomain-Finder[/bold blue] - Starting scan...\n")
    asyncio.run(main())
