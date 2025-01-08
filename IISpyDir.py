import os
import xml.etree.ElementTree as ET
import re
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor

# ASCII Art Header
def print_header():
    print(r"""
      / _ \
    \_\(_)/_/
     _//"\\_  IISpyDir
      /   \   v 0.1
    """)

# Function to parse Nmap XML and GNMAP files for IIS services
def parse_nmap_files(directory):
    targets = []

    # Iterate over all files in the specified directory
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)

        if file_name.endswith(".xml"):
            print(f"Parsing XML file: {file_name}")
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()

                for host in root.findall("host"):
                    ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            ip = addr.get("addr")
                            break

                    for port in host.findall("ports/port"):
                        protocol = port.get("protocol")
                        port_id = int(port.get("portid"))
                        state = port.find("state").get("state")
                        service = port.find("service")

                        if state == "open" and service is not None:
                            product = service.get("product", "")
                            version = service.get("version", "")
                            service_name = service.get("name", "").lower()

                            # Determine URL prefix based on service name
                            if "https" in service_name:
                                url = f"https://{ip}:{port_id}" if port_id != 443 else f"https://{ip}"
                            elif "http" in service_name:
                                url = f"http://{ip}:{port_id}" if port_id != 80 else f"http://{ip}"
                            else:
                                continue  # Skip non-HTTP/HTTPS services

                            if "IIS" in product and protocol == "tcp":
                                targets.append({
                                    "url": url,
                                    "product": product,
                                    "version": version
                                })
            except Exception as e:
                print(f"Error parsing {file_name}: {e}")

        elif file_name.endswith(".gnmap"):
            print(f"Parsing GNMAP file: {file_name}")
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        if "Ports:" in line:
                            parts = line.split()
                            ip = parts[1]
                            for port_info in line.split("Ports:")[1].split(","):
                                match = re.search(r"(\d+)/open/tcp//([^/]+)/([^/]+)/", port_info)
                                if match:
                                    port, product, service = match.groups()
                                    port = int(port)

                                    # Determine URL prefix based on service name
                                    if "https" in service.lower():
                                        url = f"https://{ip}:{port}" if port != 443 else f"https://{ip}"
                                    elif "http" in service.lower():
                                        url = f"http://{ip}:{port}" if port != 80 else f"http://{ip}"
                                    else:
                                        continue  # Skip non-HTTP/HTTPS services

                                    if "IIS" in product:
                                        targets.append({
                                            "url": url,
                                            "product": product,
                                            "version": service
                                        })
            except Exception as e:
                print(f"Error parsing {file_name}: {e}")

    return targets

# Function to run Shortscan on a target with real-time output
def run_shortscan(target, additional_args=None, timeout=30):
    url = target['url']
    print(f"Running Shortscan on {url} with timeout {timeout}s...")
    try:
        # Prepare Shortscan command
        shortscan_cmd = ["shortscan", "--timeout", str(timeout), url]
        
        # Add any additional arguments to the command
        if additional_args:
            shortscan_cmd.extend(additional_args)

        # Use Popen to stream output in real time
        process = subprocess.Popen(shortscan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Read and display output line by line
        for line in process.stdout:
            print(line.strip())  # Removed the URL prefix from output lines
        
        # Wait for the process to complete
        process.wait()

        # Check for errors
        if process.returncode != 0:
            for line in process.stderr:
                print(f"ERROR: {line.strip()}")

    except Exception as e:
        print(f"Error running Shortscan on {url}: {e}")

    finally:
        # Ensure the process is terminated
        if process and process.poll() is None:
            process.terminate()

# Main function
def main(directory, threads, timeout, additional_args):
    print_header()  # Print ASCII art header at the start
    print(f"Parsing Nmap results in directory: {directory}")
    targets = parse_nmap_files(directory)

    if not targets:
        print("No vulnerable IIS servers found.")
        return

    print(f"Found {len(targets)} target(s). Running Shortscan...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda target: run_shortscan(target, additional_args, timeout), targets)

# CLI setup
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IIS Short Filename Vulnerability Scanner using Shortscan")
    parser.add_argument("-d", "--directory", required=True, help="Directory containing Nmap result files")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Shortscan request timeout in seconds (default: 30)")
    parser.add_argument("-a", "--args", nargs="*", help="Additional arguments to pass to Shortscan (e.g., -w wordlist.txt)")
    args = parser.parse_args()

    main(args.directory, args.threads, args.timeout, args.args)
