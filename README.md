# SubDomain-Finder

A high-performance subdomain discovery tool, designed for security professionals and system administrators.

## Features

- Fast subdomain enumeration using asyncio for concurrent operations
- Brute-force subdomain discovery using customizable wordlists
- Integration with multiple third-party services:
  - VirusTotal
  - DNSdumpster
  - Certificate Transparency logs
- Multi-threaded DNS resolution
- Flexible output formats (text and JSON)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SubDomain-Finder.git
cd SubDomain-Finder

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python main.py -d example.com [options]

Options:
  -d, --domain     Target domain to scan for subdomains
  -w, --wordlist   Path to custom wordlist for brute-force (default: wordlists/default.txt)
  -o, --output     Output file path
  -f, --format     Output format (text/json) (default: text)
  -t, --threads    Number of concurrent threads (default: 10)
  -v, --verbose    Enable verbose output
```

## Example

```bash
# Basic usage
python main.py -d example.com

# Using a custom wordlist with JSON output
python main.py -d example.com -w custom_wordlist.txt -o results.json -f json

# Verbose mode with increased threads
python main.py -d example.com -t 20 -v
```

## Configuration

Create a `.env` file in the project root with your API keys:

```
VIRUSTOTAL_API_KEY=your_api_key_here
```

## API Integration

The tool integrates with the following third-party services:
- VirusTotal API
- DNSdumpster
- Certificate Transparency logs

Each service is implemented as a separate module for easy maintenance and extensibility.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by [Sublist3r](https://github.com/aboul3la/Sublist3r)

- Thanks to all third-party services for their APIs
