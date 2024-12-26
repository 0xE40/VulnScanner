import requests
from bs4 import BeautifulSoup
import os
import datetime

results = []

def log_result(message):
    """
    Log results to the console and append them to the results list
    """
    print(message)
    results.append(message)

def scan_sql_injection(url, params):
    """
    Tests for basic SQL Injection by adding common SQL payloads to GET parameters
    """
    sql_payloads = ["'", "' OR 1=1 --", "' AND 1=1 --", "' OR 'a'='a", '" OR "a"="a"']
    vulnerable = False
    log_result(f"[INFO] Testing {url} for SQL Injection...")

    for param in params:
        for payload in sql_payloads:
            test_params = params.copy()
            test_params[param] = payload  # Inject payload
            try:
                response = requests.get(url, params=test_params, timeout=5)
                if "SQL" in response.text or "syntax" in response.text or "error" in response.text:
                    log_result(f"[VULNERABLE] SQL Injection in parameter '{param}' with payload: {payload}")
                    vulnerable = True
            except requests.RequestException:
                log_result(f"[ERROR] Could not connect to {url}")

    if not vulnerable:
        log_result(f"[SAFE] No SQL Injection vulnerabilities found.")

    return vulnerable

def scan_xss(url, params):
    """
    Tests for basic Cross-Site Scripting (XSS) by injecting a harmless XSS payload
    """
    xss_payload = "<script>alert('XSS')</script>"
    vulnerable = False
    log_result(f"[INFO] Testing {url} for Cross-Site Scripting (XSS)...")

    for param in params:
        test_params = params.copy()
        test_params[param] = xss_payload
        try:
            response = requests.get(url, params=test_params, timeout=5)
            if xss_payload in response.text:
                log_result(f"[VULNERABLE] XSS vulnerability in parameter '{param}' with payload: {xss_payload}")
                vulnerable = True
        except requests.RequestException:
            log_result(f"[ERROR] Could not connect to {url}")

    if not vulnerable:
        log_result(f"[SAFE] No XSS vulnerabilities found.")

    return vulnerable

def crawl_and_discover_forms(url):
    """
    Crawls a given URL to discover all forms on the page
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        log_result(f"[INFO] Found {len(forms)} form(s) on {url}.")
        return forms
    except requests.RequestException:
        log_result(f"[ERROR] Could not connect to {url}.")
        return []

def attack_forms(url, forms):
    """
    Attacks discovered forms via SQL Injection and XSS payloads
    """
    for form in forms:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        params = {input_tag.attrs.get("name", ""): "test" for input_tag in inputs if input_tag.attrs.get("name", "")}

        form_url = f"{url}/{action}" if action.startswith("/") else action
        log_result(f"\n[INFO] Testing form on {form_url} with method {method.upper()} and parameters: {params}")

        log_result("[INFO] Testing for SQL Injection...")
        scan_sql_injection(form_url, params)

        log_result("[INFO] Testing for XSS...")
        scan_xss(form_url, params)

def save_results_to_file(url):
    """
    Save the results to a text file
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("http://", "").replace("https://", "").replace("/", "_")
    filename = f"{safe_url}_vulnerability_scan_{timestamp}.txt"

    with open(filename, "w") as file:
        file.write(f"Vulnerability Scan Results for {url}\n")
        file.write("-" * 50 + "\n\n")
        for line in results:
            file.write(line + "\n")

    log_result(f"\n[INFO] Results saved to {os.path.abspath(filename)}")

def main():
    url = input("Enter the URL of the website to scan (e.g., http://example.com): ").strip()

    log_result("[INFO] Crawling the website to discover forms...")
    forms = crawl_and_discover_forms(url)

    if forms:
        log_result("\n[INFO] Starting vulnerability testing for discovered forms...")
        attack_forms(url, forms)
    else:
        log_result("[INFO] No forms available for testing.")

    save_results_to_file(url)

    log_result("\n[INFO] Scan finished!")

if __name__ == "__main__":
    main()
