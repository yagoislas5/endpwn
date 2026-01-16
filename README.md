
# endpwn

**endpwn** is an advanced engine for discovering web endpoints and routes, designed for bug bounty and security research.  
Its goal is not just to “find URLs,” but to enumerate real, historical, and semantic routes while minimizing noise and avoiding the false positives typical of traditional crawlers.

The design prioritizes coverage without losing endpoints, clearly decoupling the phases of discovery, analysis, and validation.

---

## Installation

```bash
git clone https://github.com/yagoislas5/endpwn
cd endpwn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Basic Usage

**Full scan (discovery + analysis + validation):**
```bash
python3 endpwn.py https://example.com
```

**Enumeration without validation (only routes and endpoints):**
```bash
python3 endpwn.py https://example.com --enum-only
```

**Disable historical discovery (Wayback):**
```bash
python3 endpwn.py https://example.com --no-historical
```

**Directory-focused mode:**
```bash
python3 endpwn.py https://example.com --directory-focused
```

---

## Historical Discovery (Wayback Machine)

By default, **endpwn** includes historical routes obtained from Wayback Machine.

This enables discovery of:
- Old endpoints removed from the frontend  
- Legacy routes (.jsp, .php, .old, .bak)  
- Versioned APIs no longer documented  
- Resources still accessible but not linked  

Historical routes are not immediately validated, preventing noise and unnecessary blocking.  
Internally, Wayback routes are normalized and integrated into the same route graph as current routes.

---

## Advanced SPA Fallback Detection

**endpwn** includes a heuristic system to detect when an endpoint returns a generic fallback instead of a real route.

Examples of detected fallbacks:
- SPAs always returning `index.html`  
- Silent redirects to `/` or `/login`  
- Generic pages served by CDNs  

Detection is based on multiple combined signals:
- Structural DOM similarity  
- Content hash  
- Relative response size  
- SPA artifacts (`root`, `__next_data__`, etc.)  
- Server headers (CDN-aware)  

This reduces false positives without eliminating potentially interesting routes.

---

## What’s New (v3)

Compared to previous versions, **endpwn v3** introduces:
- Clear separation between discovery, analysis, and validation  
- `--enum-only` mode without early validation  
- Wayback Machine enabled by default  
- Improved SPA fallback detection  
- Route inference decoupled from JavaScript  
- Crawling limited by semantic depth  
- Significant noise reduction  
- Greater coverage of forgotten or legacy routes
