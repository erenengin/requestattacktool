import requests
import argparse
import threading
from queue import Queue
import sys
from itertools import product, zip_longest
import time
from bs4 import BeautifulSoup

"""
Flexible HTTP Attack Tool
This tool tests HTTP requests with customized payloads or sends plain requests. It provides error messages, response time, and specific tag/id/class content.
"""

# Default settings
q = Queue()
results = []

# HTTP request sending function
def send_request(url, method, payloads=None, headers=None, proxies=None, data=None, success_criteria=None, response_extract=None, output_filter=None, session=None, cookies=None):
    try:
        start_time = time.time()
        if session:
            req = session
        else:
            req = requests

        if method.upper() == "POST" and data:
            if payloads:
                formatted_data = data
                for payload in payloads:
                    formatted_data = formatted_data.replace("{payload}", payload, 1)
            else:
                formatted_data = data
            response = req.post(url, data=formatted_data, headers=headers, proxies=proxies, timeout=5, cookies=cookies)
        else:
            if payloads:
                formatted_url = url
                for payload in payloads:
                    formatted_url = formatted_url.replace("{payload}", payload, 1)
            else:
                formatted_url = url
            response = req.get(formatted_url, headers=headers, proxies=proxies, timeout=5, cookies=cookies)
        
        response_time = (time.time() - start_time) * 1000
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract response content
        if response_extract:
            if response_extract.startswith("id:"):
                tag_id = response_extract[3:]
                tag = soup.find(id=tag_id)
                response_content = tag.get_text(strip=True) if tag else f"ID '{tag_id}' not found"
            elif response_extract.startswith("class:"):
                tag_class = response_extract[6:]
                tag = soup.find(class_=tag_class)
                response_content = tag.get_text(strip=True) if tag else f"Class '{tag_class}' not found"
            elif response_extract in ['div', 'span', 'p', 'h1', 'h2', 'h3', 'li', 'td', 'th']:
                tags = soup.find_all(response_extract)
                response_content = tags[0].get_text(strip=True) if tags else f"Tag '{response_extract}' not found"
            else:
                tag_with_keyword = soup.find(string=lambda text: text and response_extract in text)
                response_content = tag_with_keyword if tag_with_keyword else f"'{response_extract}' not found"
        else:
            response_content = soup.get_text(strip=True)[:100]

        # Filter output
        if output_filter == "status":
            output = f"Status: {response.status_code}"
        elif output_filter == "time":
            output = f"Time: {response_time:.2f}ms"
        elif output_filter == "response":
            output = f"Response: {response_content}"
        else:
            if success_criteria and success_criteria in response.text:
                output = f"[+] Success: {payloads or 'Plain request'} - Status: {response.status_code} - Time: {response_time:.2f}ms - Response: {response_content}"
                if payloads:
                    results.append(payloads)
            else:
                output = f"[-] Failed: {payloads or 'Plain request'} - Status: {response.status_code} - Time: {response_time:.2f}ms - Response: {response_content}"
        
        print(output)
        return output
    except requests.exceptions.RequestException as e:
        response_time = (time.time() - start_time) * 1000
        output = f"[!] Error: {payloads or 'Plain request'} - Error Message: {str(e)} - Time: {response_time:.2f}ms"
        print(output)
        return output

# Worker function
def worker(args, session=None):
    while True:
        try:
            payloads = q.get_nowait()
            output = send_request(args.url, args.method, payloads, args.headers, args.proxy, args.data, args.success, args.response, args.output_filter, session, args.cookies)
            if args.output_file:
                with open(args.output_file, 'a') as f:
                    f.write(output + '\n')
            q.task_done()
        except:
            break

# Load payloads from files
def load_payloads(payload_files):
    all_payloads = []
    for payload_file in payload_files:
        try:
            with open(payload_file, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
                all_payloads.append(payloads)
        except Exception as e:
            print(f"[!] Error: Could not read payload file: {payload_file} - {str(e)}")
            sys.exit(1)
    return all_payloads

# Prepare payloads based on attack type
def prepare_payloads(args, payload_lists, session=None):
    if args.method == "GET":
        placeholder_count = args.url.count("{payload}")
    else:
        if args.data is None:
            print("[!] Error: POST method requires -d/--data parameter.")
            sys.exit(1)
        placeholder_count = args.data.count("{payload}")

    attack_type = args.attack.lower() if args.attack else None

    if not attack_type:
        output = send_request(args.url, args.method, None, args.headers, args.proxy, args.data, args.success, args.response, args.output_filter, session, args.cookies)
        if args.output_file:
            with open(args.output_file, 'a') as f:
                f.write(output + '\n')
        sys.exit(0)

    if attack_type == "sniper":
        if placeholder_count > 1 and len(payload_lists) > 1:
            print("[!] Error: Sniper only works with a single payload list.")
            sys.exit(1)
        base = ["Â§"] * placeholder_count
        for payload in payload_lists[0]:
            for i in range(placeholder_count):
                temp = base.copy()
                temp[i] = payload
                for _ in range(args.repeat):
                    q.put(temp)

    elif attack_type == "batteringram":
        if len(payload_lists) > 1:
            print("[!] Error: Battering Ram only works with a single payload list.")
            sys.exit(1)
        for payload in payload_lists[0]:
            for _ in range(args.repeat):
                q.put([payload] * placeholder_count)

    elif attack_type == "pitchfork":
        if len(payload_lists) != placeholder_count:
            print(f"[!] Error: Pitchfork requires the number of payload lists ({len(payload_lists)}) to match the number of placeholders ({placeholder_count}).")
            sys.exit(1)
        for payloads in zip(*payload_lists):
            for _ in range(args.repeat):
                q.put(payloads)

    elif attack_type == "clusterbomb":
        if len(payload_lists) != placeholder_count:
            print(f"[!] Error: Cluster Bomb requires the number of payload lists ({len(payload_lists)}) to match the number of placeholders ({placeholder_count}).")
            sys.exit(1)
        for payloads in product(*payload_lists):
            for _ in range(args.repeat):
                q.put(payloads)

# Parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Flexible HTTP Attack Tool - Tests HTTP requests with customized payloads or sends plain requests.",
        epilog="""
Usage Examples:
  1. Plain GET request:
     python tool.py -u "http://example.com"
  2. Plain POST request:
     python tool.py -u "http://example.com/login" -m POST -d "user=test&pass=123"
  3. Sniper with status only:
     python tool.py -u "http://example.com/?a={payload}" -p payloads.txt -a sniper --output-filter status
  4. Cluster Bomb with response time and file output:
     python tool.py -u "http://example.com/?a={payload}&b={payload}" -p list1.txt -p list2.txt -a clusterbomb --output-filter time --output-file results.txt
  5. POST login test with class filter and session:
     python tool.py -u "http://example.com/login" -m POST -d "user={payload}&pass={payload}" -p users.txt -p pass.txt -a clusterbomb -s "Welcome" --response class:alert --session
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., 'http://example.com/?id={payload}')")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("-p", "--payloads", action="append", help="Payload files (e.g., -p list1.txt -p list2.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-H", "--headers", help="Custom headers (e.g., 'Key:Value')", action="append")
    parser.add_argument("-x", "--proxy", help="Proxy (e.g., 'http://127.0.0.1:8080')")
    parser.add_argument("-d", "--data", default=None, help="POST data (e.g., 'user={payload}&pass={payload}')")
    parser.add_argument("-s", "--success", help="Success criterion (text to search in response)")
    parser.add_argument("-a", "--attack", default=None, choices=["sniper", "batteringram", "pitchfork", "clusterbomb"], 
                        help="Attack type: sniper, batteringram, pitchfork, clusterbomb (default: plain request)")
    parser.add_argument("-r", "--repeat", type=int, default=1, help="Number of repeats per request (default: 1)")
    parser.add_argument("--response", default=None, help="Response content: 'id:<id>', 'class:<class>', tag (e.g., 'div'), or keyword (e.g., 'error')")
    parser.add_argument("--output-filter", default=None, choices=["status", "time", "response"], 
                        help="Output filter: status, time, response (default: full output)")
    parser.add_argument("--output-file", default=None, help="File to save output (e.g., 'results.txt')")
    parser.add_argument("--session", action="store_true", help="Use session to persist cookies across requests")
    parser.add_argument("--cookies", help="Custom cookies (e.g., 'key=value')", action="append")
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()
    headers = {h.split(":")[0].strip(): h.split(":")[1].strip() for h in args.headers} if args.headers else {}
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    cookies = {c.split("=")[0].strip(): c.split("=")[1].strip() for c in args.cookies} if args.cookies else None
    session = requests.Session() if args.session else None

    if args.payloads:
        payload_lists = load_payloads(args.payloads)
        prepare_payloads(args, payload_lists, session)
        print(f"[*] Attack starting: {q.qsize()} requests (including repeats), {args.threads} threads")
        for _ in range(args.threads):
            t = threading.Thread(target=worker, args=(args, session))
            t.start()
        q.join()
    else:
        output = send_request(args.url, args.method, None, args.headers, args.proxy, args.data, args.success, args.response, args.output_filter, session, cookies)
        if args.output_file:
            with open(args.output_file, 'a') as f:
                f.write(output + '\n')

    print(f"[*] Process completed! Successful results: {results}")

if __name__ == "__main__":
    main()
