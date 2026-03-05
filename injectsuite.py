#!/usr/bin/env python3
"""
InjectSuite - Modular Injection Detection Toolkit
"""

import sys
import time
import importlib

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich import box

console = Console()

ASCII_BANNER = r"""
/==========================================================================================\
|  01001001 01001110 01001010 01000101 01000011 01010100 01010011 01010101 01000101        |
|  01001001 01010100 01000101 01000001 01001101 01010011 01001001 01010100 01010100        |
|                                                                                          |
|  ╔════════════════════════════════════════════════════════════════════════════════════╗  |
|  ║██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗███████╗██╗   ██╗██╗████████╗███████╗ ║  |
|  ║██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██║   ██║██║╚══██╔══╝██╔════╝ ║  |
|  ║██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ███████╗██║   ██║██║   ██║   █████╗   ║  |
|  ║██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ╚════██║██║   ██║██║   ██║   ██╔══╝   ║  |
|  ║██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ███████║╚██████╔╝██║   ██║   ███████╗ ║  |
|  ║╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ║  |
|  ╚════════════════════════════════════════════════════════════════════════════════════╝  |
|                                                                                          |
|  [BOOT]   ┌─[ CORE ]─────────────────────────────────────────────────────────────────┐   |
|  [INIT]   │  • Payload Engine    : ONLINE                                            │   |
|  [LOAD]   │  • Reflection Probe  : OK                                                │   |
|  [READY]  │  • Vector Modules    : SQLi | XSS | CMD                                  │   |
|  [SET]    └──────────────────────────────────────────────────────────────────────────┘   |
|                                                                                          |
\==========================================================================================/
"""

# --------------------------------------------------
# Banner Coloring
# --------------------------------------------------

def colorize_banner(ascii_banner):
    lines = []
    for line in ascii_banner.splitlines():
        text = Text(line)

        if "0100" in line:
            text.stylize("green")
        elif "===" in line or "╔" in line or "╝" in line or "╚" in line:
            text.stylize("bright_cyan")
        elif "██" in line:
            text.stylize("bold bright_cyan")
        elif "[BOOT]" in line or "[INIT]" in line or "[LOAD]" in line or "[READY]" in line or "[SET]" in line:
            text.stylize("bright_magenta")
        else:
            text.stylize("bright_cyan")

        lines.append(text)

    return lines


# --------------------------------------------------
# Banner
# --------------------------------------------------

def show_banner():

    banner_lines = colorize_banner(ASCII_BANNER)

    banner_text = Text()
    for line in banner_lines:
        banner_text.append(line)
        banner_text.append("\n")

    console.print(
        Panel.fit(
            banner_text,
            border_style="bright_cyan",
            title="[bold bright_magenta]INJECTSUITE[/bold bright_magenta]",
            box=box.SQUARE
        )
    )

    warning = Text.from_markup(
        "[bright_yellow]This tool is intended for educational and authorized security testing only.[/bright_yellow]\n"
        "[bright_red]⚠ Do NOT use this tool against live or unauthorized websites.[/bright_red]\n"
        "[bright_blue]✔ Always test in controlled environments (DVWA, Juice Shop, TestFire).[/bright_blue]"
    )

    console.print(
        Panel(
            warning,
            border_style="red",
            title="[bold red]LEGAL NOTICE[/bold red]"
        )
    )


# --------------------------------------------------
# Boot Animation
# --------------------------------------------------

def matrix_boot():

    total = 20

    for i in range(total + 1):
        percent = int((i / total) * 100)

        filled = "█" * i
        empty = "░" * (total - i)

        console.print(
            f"[green][BOOT][/green] [{filled}{empty}] {percent}%",
            end="\r"
        )

        time.sleep(0.07)

    console.print("\n[bold green]✔ System modules initialized[/bold green]\n")


# --------------------------------------------------
# Hacker typing animation
# --------------------------------------------------

def type_writer(text, speed=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()


def hacker_boot_messages():

    messages = [
        "> Initializing InjectSuite Core...",
        "> Loading Payload Engine...",
        "> Activating Reflection Probe...",
        "> Registering SQL Injection Module...",
        "> Registering XSS Module...",
        "> Registering Command Injection Module...",
        "> Modules Ready."
    ]

    for msg in messages:
        type_writer(msg)
        time.sleep(0.3)

    console.print("[bold green]✔ InjectSuite Ready[/bold green]\n")


# --------------------------------------------------
# Compact Header (used after first run)
# --------------------------------------------------

def show_compact_header():

    title = "[bold magenta]INJECTSUITE[/bold magenta]"
    subtitle = "[cyan]Modular Injection Detection Toolkit[/cyan]"

    console.print(
        Panel.fit(
            Text.from_markup(f"{title}\n{subtitle}"),
            border_style="bright_blue",
            box=box.ROUNDED
        )
    )


# --------------------------------------------------
# Scan Configuration Panel
# --------------------------------------------------

def show_scan_config():

    console.print(
        Panel(
            "[cyan]Target:[/cyan] http://testphp.vulnweb.com\n"
            "[cyan]Mode:[/cyan] Active Scan\n"
            "[cyan]Modules:[/cyan] SQLi | XSS | CMDi",
            title="[bold green]Scan Configuration[/bold green]",
            border_style="green"
        )
    )


# --------------------------------------------------
# Dynamic module loader
# --------------------------------------------------

def load_module(module_name, function_names):

    try:
        mod = importlib.import_module(module_name)
    except ModuleNotFoundError:
        console.print(f"[red]Module {module_name} not found[/red]")
        return None

    for name in function_names:
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn

    console.print(f"[red]{module_name} does not expose expected functions[/red]")
    return None


# --------------------------------------------------
# Main Menu
# --------------------------------------------------

def main_menu():

    sql_runner = load_module("scanners.sqli_scanner", ["run_sql_injection_scanner", "main"])
    xss_runner = load_module("scanners.xss_scanner", ["run_xss_scanner", "main"])
    cmdi_runner = load_module("scanners.cmdi_scanner", ["run_cmdi_scanner", "main"])

    first_run = True

    while True:

        console.clear()

        if first_run:
            matrix_boot()
            hacker_boot_messages()
            show_banner()
            first_run = False
        else:
            show_compact_header()

        console.print()

        console.print(
            Panel.fit(
                "[bold cyan]Select an option[/bold cyan]\n\n"
                "[1] Run SQL Injection Scanner\n"
                "[2] Run XSS Scanner\n"
                "[3] Run Command Injection Scanner\n"
                "[4] Exit\n",
                title="[bold magenta]Main Menu[/bold magenta]",
                border_style="bright_blue"
            )
        )

        choice = Prompt.ask(
            "[green]Enter choice[/green]",
            choices=["1", "2", "3", "4"],
            default="1"
        )

        if choice == "1":

            # show_scan_config()

            if sql_runner:
                console.print("[yellow]Launching SQL Injection Scanner...[/yellow]\n")
                sql_runner()
            else:
                console.print("[red]SQL scanner module missing[/red]")

            Prompt.ask("\nPress Enter to return")

        elif choice == "2":

            # show_scan_config()

            if xss_runner:
                console.print("[yellow]Launching XSS Scanner...[/yellow]\n")
                xss_runner()
            else:
                console.print("[red]XSS scanner module missing[/red]")

            Prompt.ask("\nPress Enter to return")

        elif choice == "3":

            # show_scan_config()

            if cmdi_runner:
                console.print("[yellow]Launching Command Injection Scanner...[/yellow]\n")
                cmdi_runner()
            else:
                console.print("[red]CMDi scanner module missing[/red]")

            Prompt.ask("\nPress Enter to return")

        elif choice == "4":

            console.print("\n[bold green]Goodbye — stay ethical![/bold green]\n")
            break


# --------------------------------------------------

if __name__ == "__main__":
    main_menu()