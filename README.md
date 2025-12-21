

# endpwn — Bug Bounty Recon (JS Mapper)

`endpwn` is a Python 3.13+ tool designed to map and collect JavaScript files from a target domain. It crawls pages within the same domain, identifies linked JavaScript files, and optionally saves the results in JSON format. This helps researchers discover potential endpoints, routes, and hidden parameters inside exposed JavaScript.

---

## Features
- Asynchronous crawler using `httpx` and `asyncio` for efficient scanning.  
- Automatic detection of JavaScript files linked within the same domain.  
- Configurable page limit (`MAX_PAGES`) to prevent infinite crawling.  
- JSON export of discovered JavaScript files.  
- Internal link filtering to keep the crawl restricted to the target domain.  

---

## Requirements
- Python 3.13+  
- Libraries:
  - `httpx`
  - `beautifulsoup4`

Install dependencies:
```bash
pip install httpx beautifulsoup4
```

---

## Usage
Run the script with the `-u` parameter to specify the target domain:

```bash
python3 endpwn.py -u example.com
```

### Options
- `-u, --url` → Target domain (e.g., `example.com` or `https://example.com`).  
- `--json` → Save results to a JSON file.  

Example:
```bash
python3 endpwn.py -u target.com --json results.json
```

---

## Notes
This tool is intended for ethical security research and should only be used on domains where you have explicit authorization.  

---
