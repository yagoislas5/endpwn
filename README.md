

# endpwn — Bug Bounty Recon (JS Mapper)
---

# Advanced Recursive Endpoint Discovery Engine

An advanced Python-based engine for **recursive HTTP endpoint discovery, validation, and classification**, designed for **offensive reconnaissance and access-control analysis**.

The tool focuses on **accurate surface mapping** rather than raw crawling volume, with strong internal logic to reduce false positives commonly produced by modern SPAs and authentication flows.

---

## Features

* Recursive endpoint discovery from:

  * HTML responses
  * JavaScript files
  * Dynamically inferred paths
* Intelligent endpoint validation:

  * HEAD-first probing
  * Conditional GET requests
* Robust **SPA fallback and silent redirect detection**
* Automatic filtering of:

  * Home page redirects
  * Login redirects
  * Client-side SPA fallbacks
* Endpoint classification by HTTP status
* Controlled **403 bypass testing** using semantic path variants
* One-time bypass execution per endpoint (no repeated noise)
* Canonical path deduplication
* Async execution with concurrency limits
* Internal state tracking for endpoints and bypass attempts
* Clean, structured output suitable for manual analysis or reporting

---

## Internal Workflow

1. Home page fingerprinting (hash, content length, content type)
2. Initial endpoint discovery
3. Endpoint validation and status classification
4. SPA fallback detection and filtering
5. Dynamic endpoint generation (only for valid responses)
6. Controlled 403 bypass attempts
7. Final result aggregation and deduplication

---

## SPA Fallback Detection

The engine detects scenarios where an endpoint returns `200 OK` but serves:

* The application home page
* A login page
* A client-side SPA fallback route

Such responses are excluded from:

* Dynamic path generation
* Debug or test endpoint probing
* Bypass result reporting

This significantly reduces false positives on modern web applications.

---

## 403 Handling and Bypass Logic

* All `403 Forbidden` endpoints are reported with their original URL.
* Each endpoint is tested for bypass **only once**.
* Bypass results are validated against the original response.
* Responses matching home or fallback fingerprints are discarded.
* Failed bypass attempts are explicitly marked.

---

## Requirements

* Python 3.9+
* Dependencies:

  * `httpx`
  * `asyncio`
  * `hashlib`
  * `re`
  * `json`

---

## Use
python3 endpwn.py example.com
