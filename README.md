# IISpyDir

**IISpyDir** is a Python tool for scanning Microsoft IIS servers for short filename enumeration vulnerabilities. It automates the process of identifying IIS servers from Nmap results, determining vulnerable targets, and using the [Shortscan](https://github.com/bitquark/shortscan) tool to exploit the vulnerability.

## Features
- Parses **Nmap** XML and GNMAP files to identify IIS servers.
- Automatically determines HTTP/HTTPS protocols based on Nmap service detection.
- Runs the [Shortscan](https://github.com/bitquark/shortscan) tool against detected IIS servers.
- Real-time output for quick feedback.
- Multi-threaded for efficient scanning.

## Requirements
- Python 3.7 or higher
- [Shortscan](https://github.com/bitquark/shortscan) installed and accessible in your PATH.
- Nmap output files (`.xml`, `.gnmap`) with service detection (`-sV`).

## Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/iispydir.git
cd iispydir
```

### Install Dependencies
Install Python dependencies:
```bash
pip install -r requirements.txt
```

Install [Shortscan](https://github.com/bitquark/shortscan):
```bash
go install github.com/bitquark/shortscan/cmd/shortscan@latest
```
Ensure the `shortscan` binary is in your system PATH.

## Usage

### Run the Tool
1. Generate Nmap results:
   ```bash
   nmap -p 80,443,8080,8443 --open -sV -oA nmap_results 192.168.1.0/24
   ```

2. Execute IISpyDir:
   ```bash
   python iispydir.py -d nmap_results/ --timeout 30
   ```

### CLI Options
| Option         | Description                                                                                   |
|----------------|-----------------------------------------------------------------------------------------------|
| `-d`/`--directory` | Directory containing Nmap `.xml` or `.gnmap` files.                                           |
| `-t`/`--threads`   | Number of threads for concurrent scanning (default: 5).                                     |
| `--timeout`        | Timeout for each Shortscan request (default: 30 seconds).                                   |
| `-a`/`--args`      | Additional arguments to pass to Shortscan (e.g., `--wordlist my_wordlist.txt`).             |

### Example
```bash
python iispydir.py -d nmap_results/ --timeout 60 -t 10 -a --wordlist custom_wordlist.txt
```

## Output Example
```
      / _ \
    \_\(_)/_/
     _//"\\_  IISpyDir
      /   \   v 0.1

Parsing Nmap results in directory: nmap_results/
Found 2 target(s). Running Shortscan...
Running Shortscan on http://192.168.1.10 with timeout 30s...
🌀 Shortscan v0.9.2 · an IIS short filename enumeration tool by bitquark
Testing for shortname enumeration vulnerability...
Vulnerable! Enumerating files...
Found file: WEB~1.CONFIG -> web.config
```

## How It Works
1. **Parse Nmap Results**:
   - Reads `.xml` or `.gnmap` files in the specified directory.
   - Identifies open HTTP/HTTPS services running on IIS servers.

2. **Determine HTTP/HTTPS Protocol**:
   - Uses the Nmap `service` field to determine whether to use `http://` or `https://`.

3. **Run Shortscan**:
   - Executes Shortscan for each identified IIS server to test for vulnerabilities.

4. **Display Results**:
   - Outputs Shortscan results in real-time.

## License
This project is licensed under the [MIT License](LICENSE).

## Acknowledgments
- [BitQuark](https://github.com/bitquark) for the **Shortscan** tool.
- ASCII art inspired by spider designs.
