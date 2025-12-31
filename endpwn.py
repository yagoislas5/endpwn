#!/usr/bin/env python3
# =========================
# ENDPWN V1.0.3
# =========================
import argparse
import asyncio
import json
import re
import sys
import signal
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict
from typing import Set, Dict, List, Any, Tuple
import esprima
import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import pickle
import hashlib

init(autoreset=True)

# =========================
# CONFIGURACIÓN GLOBAL
# =========================
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36"
TIMEOUT = 10
MAX_HTML_PAGES = 50
MAX_CONCURRENCY = 50
MAX_ROUTE_LIMIT = 1000  # Configurable limit for routes only
IGNORE_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css",
)
NOISE_JS = (
    "google-analytics", "gtag", "googletagmanager",
    "hotjar", "mixpanel", "segment",
    "sentry", "datadog", "newrelic",
    "clarity", "fullstory",
)
ENDPOINT_REGEX = re.compile(
    r'(["\'`])((?:/|\.\./|\./|https?:\/\/)[^"\'`\s]+(?:\.(?:js|json|php|bak|txt|xml|html|css|py|rb|asp|aspx|jsp|sql|db|zip|tar|gz|7z|rar|log|conf|config|ini|yaml|yml|toml|env|htaccess|htpasswd|git|svn|cvs|bak|~|old|backup|swp|tmp|temp|swo|swp|bak1|bak2|bak3))?)(\?.*)?\1',
    re.I
)
DYNAMIC_PATTERNS = re.compile(r'/(:[^/]+|\{[^}]+\}|\$\{[^}]+\})')
REACT_ROUTE_KEYS = ("path", "to", "href")
REACT_ROUTE_FUNCS = ("navigate", "push", "replace", "Link", "useNavigate")
FETCH_FUNCS = ("fetch", "axios", "XMLHttpRequest", "$http")  # Added for semantic extraction
CLASSIFY_REGEX = {
    "auth": re.compile(r"auth|login|token|oauth", re.I),
    "admin": re.compile(r"admin|manage|panel|internal", re.I),
    "api": re.compile(r"/api/|/v\d+/", re.I),
    "graphql": re.compile(r"graphql", re.I),
    "debug": re.compile(r"debug|test|staging", re.I),
    "upload": re.compile(r"upload|file|media", re.I),
    "export": re.compile(r"export|download", re.I),
    "backup": re.compile(r"\.bak|\.old|\.backup|\.swp|\.tmp", re.I),
    "sensitive": re.compile(r"\.env|\.git|\.svn|config\.|secret|key|pass|token|private|credentials", re.I),
    "payment": re.compile(r"pay(ment)?|bill(ing)?|checkout|stripe|paypal|invoice|subscri(be|ption)|charge|order", re.I),
    "config": re.compile(r"config|settings|setup|preferences", re.I),
    "user": re.compile(r"user|account|profile|member", re.I),
    "data": re.compile(r"data|db|database|sql|query", re.I),
}
CLASSIFY_COLORS = {
    "auth": Fore.BLUE,
    "admin": Fore.RED,
    "api": Fore.GREEN,
    "graphql": Fore.MAGENTA,
    "debug": Fore.YELLOW,
    "upload": Fore.CYAN,
    "export": Fore.WHITE,
    "backup": Fore.LIGHTRED_EX,
    "sensitive": Fore.LIGHTMAGENTA_EX,
    "payment": Fore.LIGHTGREEN_EX,
    "config": Fore.LIGHTYELLOW_EX,
    "user": Fore.LIGHTBLUE_EX,
    "data": Fore.LIGHTCYAN_EX,
    "other": Fore.LIGHTBLACK_EX,
}
STATUS_COLORS = {
    200: Fore.GREEN, 201: Fore.GREEN, 204: Fore.GREEN,
    301: Fore.YELLOW, 302: Fore.YELLOW,
    401: Fore.RED, 403: Fore.RED,
    404: Fore.LIGHTBLACK_EX, 500: Fore.RED,
}
CLASS_PRIORITY = {
    "admin": 10,
    "payment": 9,
    "sensitive": 8,
    "data": 8,
    "auth": 7,
    "config": 7,
    "api": 6,
    "graphql": 5,
    "user": 5,
    "debug": 4,
    "upload": 3,
    "export": 2,
    "backup": 1,
    "other": 0,
}
MAX_JS_DEPTH = 10
EXPLOIT_VALUES = ["admin", "debug", "internal", "1", "0", "-1", "test", "user", "true", "false", "null", "root", "guest"]  # Expanded with more reasonable variants
CONTEXT_VALUES = {
    "admin": ["root", "superuser", "sysadmin"],
    "user": ["me", "self", "current", "guest", "anonymous"],
    "debug": ["enabled", "disabled", "on", "off"],
    "auth": ["token", "session", "oauth"],
    "api": ["v1", "v2", "beta"],
    "payment": ["checkout", "invoice", "order"],
    "other": []
}
MAX_JSON_DEPTH = 5
SEMANTIC_DEPTH_LIMIT = 5  # Limit crawling by semantic depth (e.g., path segments)
BACKUP_EXTS = [".bak", ".old", "~", ".swp", ".txt", ".log", ".config", ".ini", ".yaml", ".yml", ".toml", ".env", ".backup"]
VARIANT_FILE_EXTS = (".js", ".json", ".php", ".xml", ".txt", ".config")

# =========================
# ESTADO GLOBAL
# =========================
class State:
    def __init__(self, max_requests: int, directory_focused: bool, route_limit: int):
        self.max_requests = max_requests
        self.requests = 0
        self.stop = False
        self.seen_js: Set[str] = set()
        self.js_graph: Dict[str, Set[str]] = defaultdict(set)
        self.endpoints: Dict[str, Dict[str, Any]] = {}  # All collected, with metadata
        self.routes: Set[str] = set()  # Pure routes (directories)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self.canon_to_original: Dict[str, str] = {}
        self.js_list: List[str] = []
        self.php_list: List[Dict] = []
        self.ep_list: List[Dict] = []
        self.base_netloc = ""
        self._processing_variants = set()
        self.successful_bypasses: List[str] = []
        self.home_metrics: Dict[str, Any] = None
        self.dynamic_urls: List[str] = []
        self.bypassed: Set[str] = set()
        self.directory_focused = directory_focused
        self.route_limit = route_limit
        self.base_domain = '.'.join(self.base_netloc.split('.')[-2:]) if len(self.base_netloc.split('.')) > 1 else self.base_netloc

    def can_request(self) -> bool:
        return self.requests < self.max_requests and not self.stop

    def register_request(self, url: str):
        self.requests += 1

    def classify(self, url: str) -> str:
        for k, rx in CLASSIFY_REGEX.items():
            if rx.search(url):
                return k
        return "other"

    def canonical_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path
            path = re.sub(r'/:[^/]+', '/<dynamic>', path)
            path = re.sub(r'/\{[^}]+\}', '/<dynamic>', path)
            path = re.sub(r'/\$\{[^}]+\}', '/<dynamic>', path)
            path = path.rstrip('/') if path != '/' else '/'
            query_parts = parse_qs(parsed.query)
            sorted_items = [(k, v) for k in sorted(query_parts) for v in sorted(query_parts[k])]
            sorted_query = urlencode(sorted_items, doseq=True)
            return parsed._replace(path=path, query=sorted_query, fragment='').geturl()
        except:
            return url

    def extract_params(self, url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            return list(parse_qs(parsed.query).keys())
        except:
            return []

    def is_route(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in IGNORE_EXT):
            return False
        if '.' in path.split('/')[-1]:
            return False
        return True

    async def add_endpoint(self, url: str, source: str, mark_doubtful: bool = False, allow_host_mismatch: bool = False):
        if url.lower().endswith(IGNORE_EXT):
            return
        netloc = urlparse(url).netloc
        domain = '.'.join(netloc.split('.')[-2:]) if len(netloc.split('.')) > 1 else netloc
        if source == "historical" and allow_host_mismatch and domain == self.base_domain:
            pass  # Allow for historical
        elif netloc != self.base_netloc and not netloc.endswith("." + self.base_netloc):
            return
        canon = self.canonical_url(url)
        if canon in self.canon_to_original:
            return  # Dedupe
        self.canon_to_original[canon] = url
        cls = self.classify(url)
        params = self.extract_params(url)
        has_params = bool(params)
        is_dynamic = bool(DYNAMIC_PATTERNS.search(urlparse(url).path))
        is_route = self.is_route(url)
        if is_route and len(self.routes) >= self.route_limit and not self.directory_focused:
            return  # Limit routes if not focused
        host_mismatch = (netloc != self.base_netloc and not netloc.endswith("." + self.base_netloc))
        self.endpoints[url] = {
            "url": url,
            "source": source,
            "class": cls,
            "status": None,
            "content_type": None,
            "params": params,
            "has_params": has_params,
            "http_method": None,
            "headers": {},
            "body_params": [],
            "sensitive": False,
            "is_dynamic": is_dynamic,
            "is_route": is_route,
            "fallback": False,
            "doubtful": mark_doubtful,  # Mark if uncertain
            "inferred": False,
            "historical": False,
            "fallback_candidate": False,  # New flag for potential fallback
            "host_mismatch": host_mismatch,
            "fallback_status": None,  # None, 'confirmed', 'uncertain'
        }
        if is_dynamic:
            self.dynamic_urls.append(url)
        if is_route:
            self.routes.add(url)

# =========================
# LOGGING
# =========================
def log_info(msg: str):
    print(f"{Fore.CYAN}[+] {msg}{Style.RESET_ALL}")

def log_js(msg: str):
    print(f"{Fore.YELLOW}[JS] {msg}{Style.RESET_ALL}")

def log_ep(msg: str, status: int = None, cls: str = "other"):
    color = STATUS_COLORS.get(status, Fore.GREEN) if status else Fore.GREEN
    class_color = CLASSIFY_COLORS.get(cls, Fore.LIGHTBLACK_EX)
    print(f"{color}[EP] {class_color}{msg}{Style.RESET_ALL}")

def log_err(msg: str):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")

def log_progress(msg: str):
    print(f"{Fore.LIGHTBLUE_EX}[PROG] {msg}{Style.RESET_ALL}")

# =========================
# UTILIDADES
# =========================
def same_domain(url: str, base: str, allow_sub: bool) -> bool:
    try:
        u = urlparse(url).netloc
        b = urlparse(base).netloc
        return u == b or (allow_sub and u.endswith("." + b))
    except:
        return False

def normalize(base: str, link: str) -> str | None:
    try:
        return urljoin(base, link.strip())
    except:
        return None

def ignored(url: str) -> bool:
    return url.lower().endswith(IGNORE_EXT)

def is_noise_js(url: str) -> bool:
    return any(n in url.lower() for n in NOISE_JS)

def alternate_case(s: str) -> str:
    return ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(s))

def get_dom_metrics(html: str) -> Tuple[int, int, int, bool, bool, int, bool]:
    soup = BeautifulSoup(html, "html.parser")
    forms = len(soup.find_all('form'))
    scripts = len(soup.find_all('script'))
    
    def max_depth(element, depth=0):
        children_with_contents = [child for child in element.contents if hasattr(child, 'contents')]
        if not children_with_contents:
            return depth
        return max(max_depth(child, depth + 1) for child in children_with_contents)
    
    dom_depth = max_depth(soup)
    has_bootstrap = any("root" in str(tag) or "app" in str(tag) for tag in soup.find_all(id=True))
    has_js_redirect = bool(re.search(r'window\.location|history\.pushstate', html, re.I))
    links = len(soup.find_all('a'))  # Added for more robustness
    has_framework = any(x in html.lower() for x in ["react", "angular", "vue", "svelte", "next.js", "nuxt"])  # Expanded frameworks
    return forms, scripts, dom_depth, has_bootstrap, has_js_redirect, links, has_framework

def metrics_similar(m1: Tuple, m2: Tuple) -> bool:
    f1, s1, d1, b1, r1, l1, fw1 = m1
    f2, s2, d2, b2, r2, l2, fw2 = m2
    return (
        abs(f1 - f2) <= 1 and
        abs(s1 - s2) <= 2 and
        abs(d1 - d2) <= 3 and
        abs(l1 - l2) <= 5 and  # Added tolerance for links
        b1 == b2 and
        r1 == r2 and
        fw1 == fw2
    )

def is_fallback_response(original_url: str, r: httpx.Response, home_metrics: Tuple, home_hash: str, home_length: int, home_content_type: str) -> str:
    signals = 0
    final_url = str(r.url)
    if final_url != original_url and urlparse(final_url).path in ("/", "/login", "/login/"):
        signals += 1
    content_type = r.headers.get("content-type", "")
    if "text/html" not in content_type:
        return 'no'
    this_metrics = get_dom_metrics(r.text)
    if metrics_similar(this_metrics, home_metrics):
        signals += 1
    this_hash = hashlib.md5(r.content).hexdigest()
    if this_hash == home_hash:
        signals += 1
    if abs(len(r.content) - home_length) < 500:
        signals += 1
    body = r.text.lower()
    if any(x in body for x in ["react-dom", "angular", "vue", "svelte", "next.js", "nuxt.js"]):
        signals += 1
    # Distinguish types
    if 'cloudflare' in r.headers.get('server', '').lower() or 'akamai' in r.headers.get('server', '').lower():
        signals -= 1  # Possible CDN generic
    if 'login' in body or 'signin' in body:
        signals -= 0.5  # Possible login reuse
    if signals >= 3:
        return 'confirmed'
    elif signals >= 1.5:
        return 'uncertain'
    return 'no'

def infer_parent_routes(url: str) -> List[str]:
    parsed = urlparse(url)
    segments = parsed.path.strip('/').split('/')
    parents = []
    current = ''
    for seg in segments[:-1]:  # Exclude leaf
        current += '/' + seg
        parent = parsed._replace(path=current.rstrip('/') or '/', query='', fragment='').geturl()
        parents.append(parent)
    return parents

# =========================
# DISCOVERY PHASE
# =========================
class JSAnalyzer:
    def __init__(self, base_url: str, allow_subdomains: bool, state: State):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js_depth: Dict[str, int] = {}
        self.state = state

    async def analyze_js(self, client: httpx.AsyncClient, url: str, depth: int = 0):
        if url in self.state.seen_js or depth > MAX_JS_DEPTH:
            return
        if url.lower().endswith(".js") and "://" in url and not is_noise_js(url):
            self.state.js_list.append(url)
            log_js(url)
        self.state.seen_js.add(url)
        try:
            self.state.register_request(url)
            r = await client.get(url, timeout=TIMEOUT)
            code = r.text
            # Regex fallback
            for _, path, _ in ENDPOINT_REGEX.findall(code):
                ep = normalize(url, path)
                if ep and same_domain(ep, self.base, self.allow_subdomains) and not ignored(ep):
                    await self.state.add_endpoint(ep, "js-regex", mark_doubtful=True)

            # Improved AST walking for semantic intent
            try:
                tree = esprima.parseScript(code, tolerant=True)
                async def walk(node):
                    if isinstance(node, dict):
                        node_type = node.get("type")
                        if node_type == "CallExpression":
                            callee = node.get("callee", {})
                            if callee.get("type") == "Identifier" and callee.get("name") in FETCH_FUNCS:
                                args = node.get("arguments", [])
                                if args and args[0].get("type") == "Literal" and isinstance(args[0].get("value"), str):
                                    val = args[0]["value"]
                                    if val.startswith("/") or val.startswith("http"):
                                        ep = normalize(url, val)
                                        if ep:
                                            await self.state.add_endpoint(ep, "js-fetch")
                            elif callee.get("type") == "Identifier" and callee.get("name") in REACT_ROUTE_FUNCS:
                                args = node.get("arguments", [])
                                if args and args[0].get("type") == "Literal":
                                    val = args[0]["value"]
                                    ep = normalize(url, val)
                                    if ep:
                                        await self.state.add_endpoint(ep, "js-route")
                        for v in node.values():
                            if isinstance(v, (dict, list)):
                                await walk(v)
                    elif isinstance(node, list):
                        for i in node:
                            await walk(i)
                await walk(tree.body)  # Walk body
            except Exception as e:
                log_err(f"AST error in {url}: {e}")

            # Imports
            import_rx = re.compile(r'import\((["\'`])(.+?)\1\)', re.I)
            for _, imp_path in import_rx.findall(code):
                imp_url = normalize(url, imp_path)
                if imp_url and same_domain(imp_url, self.base, self.allow_subdomains) and not ignored(imp_url):
                    await self.analyze_js(client, imp_url, depth + 1)

            # Sourcemap
            if url.endswith(".js"):
                await self.analyze_sourcemap(client, url)
        except Exception as e:
            log_err(f"Error analyzing JS {url}: {e}")

    async def analyze_sourcemap(self, client: httpx.AsyncClient, js_url: str):
        map_url = js_url + ".map"
        try:
            self.state.register_request(map_url)
            r = await client.get(map_url, timeout=TIMEOUT)
            if r.status_code == 200:
                sm = r.json()
                for orig in sm.get("sources", []):
                    clean_path = re.sub(r'^(webpack:///\.?/|~|@|\?\?)/?', '', orig)
                    ep = normalize(js_url, clean_path)
                    if ep and same_domain(ep, self.base, self.allow_subdomains) and not ignored(ep) and not is_noise_js(ep):
                        await self.state.add_endpoint(ep, "sourcemap-path")
        except:
            pass

class HTMLCrawler:
    def __init__(self, base_url: str, allow_subdomains: bool, js_engine: JSAnalyzer, state: State):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js = js_engine
        self.visited: Set[str] = set()
        self.queue: List[str] = [base_url]
        self.state = state

    async def crawl(self, client: httpx.AsyncClient):
        while self.queue and len(self.visited) < MAX_HTML_PAGES and self.state.can_request():
            url = self.queue.pop(0)
            if url in self.visited:
                continue
            # Check semantic depth
            path_segments = len(urlparse(url).path.strip('/').split('/'))
            if path_segments > SEMANTIC_DEPTH_LIMIT:
                continue
            self.visited.add(url)
            log_info(f"HTML {url} ({len(self.visited)}/{MAX_HTML_PAGES})")
            try:
                self.state.register_request(url)
                r = await client.get(url, timeout=TIMEOUT)
                if "text/html" not in r.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                # Extract scripts
                for s in soup.find_all("script", src=True):
                    js_url = normalize(url, s["src"])
                    if js_url and same_domain(js_url, self.base, self.allow_subdomains) and not ignored(js_url) and not is_noise_js(js_url):
                        await self.js.analyze_js(client, js_url)
                # Extract links/forms
                for tag in soup.find_all(["a", "form"]):
                    attr = tag.get("href") or tag.get("action")
                    if attr:
                        nxt = normalize(url, attr)
                        if nxt and same_domain(nxt, self.base, self.allow_subdomains) and not ignored(nxt):
                            await self.state.add_endpoint(nxt, "html")
                            if len(self.visited) < MAX_HTML_PAGES:
                                # Prioritize routes in directory-focused
                                if self.state.directory_focused and self.state.is_route(nxt):
                                    self.queue.insert(0, nxt)  # Prioritize by inserting front
                                else:
                                    self.queue.append(nxt)
            except Exception as e:
                log_err(f"Error crawling {url}: {e}")

async def historical_discover(client: httpx.AsyncClient, base_url: str, state: State):
    base_netloc = urlparse(base_url).netloc
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={base_netloc}/*&output=json&fl=original&collapse=urlkey&limit=1000"
    try:
        state.register_request(cdx_url)
        r = await client.get(cdx_url, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for entry in data[1:]:
                ep = entry[0]
                if same_domain(ep, base_url, False) or '.'.join(urlparse(ep).netloc.split('.')[-2:]) == state.base_domain:
                    await state.add_endpoint(ep, "historical", mark_doubtful=True, allow_host_mismatch=True)
                    state.endpoints[ep]["historical"] = True
                    state.endpoints[ep]["doubtful"] = True  # Mark as doubtful since archived
    except Exception as e:
        log_err(f"Historical discovery error: {e}")

# =========================
# ANALYSIS PHASE
# =========================
async def analyze_endpoints(state: State):
    # Infer parents for all
    for url in list(state.endpoints.keys()):
        parents = infer_parent_routes(url)
        for parent in parents:
            await state.add_endpoint(parent, "inferred-parent", mark_doubtful=True)
            state.endpoints[parent]["inferred"] = True

    # Handle dynamics
    for dyn_url in list(set(state.dynamic_urls)):
        if dyn_url not in state.endpoints:
            continue
        source = state.endpoints[dyn_url]["source"]
        parsed = urlparse(dyn_url)
        clean_path = DYNAMIC_PATTERNS.sub('', parsed.path)
        clean_path = re.sub(r'//+', '/', clean_path)
        clean_url = parsed._replace(path=clean_path, query='', fragment='').geturl()
        await state.add_endpoint(clean_url, source + "-clean", mark_doubtful=True)
        state.endpoints[clean_url]["fallback_candidate"] = True  # Mark as potential fallback

        # Generate variants
        cls = state.endpoints[dyn_url]["class"]
        values = EXPLOIT_VALUES + CONTEXT_VALUES.get(cls, [])
        for val in values:
            var_path = DYNAMIC_PATTERNS.sub(lambda m: f'/{val}', parsed.path)
            var_path = re.sub(r'//+', '/', var_path)
            var_url = parsed._replace(path=var_path, query='', fragment='').geturl()
            if var_url != dyn_url:
                await state.add_endpoint(var_url, source + "-variant", mark_doubtful=True)
                state.endpoints[var_url]["inferred"] = True

    # Generate backup variants for file-like endpoints
    for url in list(state.endpoints.keys()):
        if url.lower().endswith(VARIANT_FILE_EXTS):
            source = state.endpoints[url]["source"]
            for ext in BACKUP_EXTS:
                var_url = url + ext
                await state.add_endpoint(var_url, source + "-backup", mark_doubtful=True)
                state.endpoints[var_url]["inferred"] = True

# =========================
# VALIDATION PHASE
# =========================
async def get_home_metrics(client: httpx.AsyncClient, home_url: str, state: State):
    async with state.semaphore:
        if not state.can_request():
            return
        state.register_request(home_url)
        try:
            r = await client.get(home_url, timeout=TIMEOUT)
            if r.status_code == 200 and 'text/html' in r.headers.get("content-type", ""):
                state.home_content_type = r.headers.get("content-type", "")
                state.home_length = len(r.content)
                state.home_hash = hashlib.md5(r.content).hexdigest()
                state.home_metrics = get_dom_metrics(r.text)
        except Exception as e:
            log_err(f"Error getting home metrics: {e}")
            state.home_metrics = (0, 0, 0, False, False, 0, False)  # Fallback to zero metrics
            state.home_length = 0
            state.home_hash = ''

async def check_if_fallback(client: httpx.AsyncClient, url: str, state: State) -> str:
    async with state.semaphore:
        if not state.can_request():
            return 'no'
        try:
            state.register_request(url)
            r_head = await client.head(url, timeout=TIMEOUT)
            if r_head.status_code in (301, 302, 303, 307, 308):
                location = r_head.headers.get("location", "")
                parsed_loc = urlparse(location)
                if parsed_loc.path in ("/", "/login", "/login/"):
                    return 'confirmed'
        except:
            pass
        try:
            state.register_request(url)
            r = await client.get(url, timeout=TIMEOUT)
            status = r.status_code
            if status != 200:
                return 'no'
            if state.home_metrics is None:
                # Degraded mode
                content_type = r.headers.get("content-type", "")
                if "text/html" not in content_type:
                    return 'no'
                if r.headers.get('server', '').lower() in ['cloudflare', 'akamai']:
                    return 'uncertain'
                if len(r.content) < 1000:  # Arbitrary small
                    return 'uncertain'
                return 'no'
            return is_fallback_response(url, r, state.home_metrics, state.home_hash, state.home_length, state.home_content_type)
        except:
            return 'no'

async def try_bypasses(client: httpx.AsyncClient, url: str, original_response: httpx.Response, state: State):
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == '/':
        return
    rel_path = path.lstrip('/')
    variant_configs = [
        {'path': path + '/.', 'netloc': parsed.netloc},
        {'path': '//' + rel_path + '//', 'netloc': parsed.netloc},
        {'path': path + '/..', 'netloc': parsed.netloc + '.'},
        {'path': '/.' + rel_path, 'netloc': parsed.netloc},
        {'path': ':/' + rel_path, 'netloc': parsed.netloc + '.'},
        {'path': '//;/' + rel_path, 'netloc': parsed.netloc},
        {'path': path.rstrip('/') + '..;/', 'netloc': parsed.netloc},
        {'path': '/' + alternate_case(rel_path), 'netloc': parsed.netloc},
        {'path': '/%2e/' + rel_path, 'netloc': parsed.netloc},
        {'path': '/%2e%2e/' + rel_path, 'netloc': parsed.netloc},
        {'path': '/%252e/' + rel_path, 'netloc': parsed.netloc},
        {'path': '/' + rel_path + '%2f', 'netloc': parsed.netloc},
        {'path': '/;%2f' + rel_path, 'netloc': parsed.netloc},
        {'path': '/.%2f' + rel_path, 'netloc': parsed.netloc},
    ]
    orig_len = len(original_response.content)
    orig_type = original_response.headers.get('Content-Type', '')
    orig_hash = hashlib.md5(original_response.content).hexdigest()
    for config in variant_configs:
        var_url = parsed._replace(netloc=config['netloc'], path=config['path'], query='', fragment='').geturl()
        try:
            async with state.semaphore:
                if not state.can_request():
                    return
                state.register_request(var_url)
                r_head = await client.head(var_url, timeout=TIMEOUT)
                if r_head.status_code == 200:
                    state.register_request(var_url)
                    r_var = await client.get(var_url, timeout=TIMEOUT)
                    if r_var.status_code == 200:
                        var_len = len(r_var.content)
                        var_type = r_var.headers.get('Content-Type', '')
                        var_hash = hashlib.md5(r_var.content).hexdigest()
                        if var_len != orig_len or var_type != orig_type or var_hash != orig_hash:
                            state.successful_bypasses.append(var_url)
                            state.bypassed.add(url)
        except:
            pass

async def validate_url(client: httpx.AsyncClient, url: str, state: State, verbose: bool):
    async with state.semaphore:
        if not state.can_request():
            return
        try:
            state.register_request(url)
            r = await client.head(url, timeout=TIMEOUT)
            if r.status_code in (404, 405):
                return
        except:
            try:
                await asyncio.sleep(1)
                state.register_request(url)
                r = await client.head(url, timeout=TIMEOUT)
            except:
                return
        try:
            state.register_request(url)
            r = await client.get(url, timeout=TIMEOUT)
            status = r.status_code
            if status != 404:
                state.endpoints[url]["status"] = status
                state.endpoints[url]["content_type"] = r.headers.get("content-type", "")
                cls = state.endpoints[url]["class"]
                fallback_status = 'no'
                if status in (200, 403) and "text/html" in state.endpoints[url]["content_type"]:
                    fallback_status = await check_if_fallback(client, url, state)
                state.endpoints[url]["fallback_status"] = fallback_status
                if fallback_status == 'confirmed':
                    state.endpoints[url]["fallback"] = True
                if verbose:
                    log_ep(f"{url} [{status}] ({cls})", status=status, cls=cls)
                if "application/json" in state.endpoints[url]["content_type"]:
                    try:
                        data = r.json()
                        await extract_from_json(data, url, client, state)
                    except:
                        pass
                if status == 403:
                    await try_bypasses(client, url, r, state)
                # Removed recursive validate_url for backups; handled in analysis
                if status in (200, 401, 403):
                    entry = {
                        "url": url,
                        "status": status,
                        "class": cls,
                        "priority": CLASS_PRIORITY.get(cls, 0),
                        "is_dynamic": state.endpoints[url].get("is_dynamic", False),
                        "fallback": state.endpoints[url].get("fallback", False),
                        "doubtful": state.endpoints[url].get("doubtful", False),
                        "inferred": state.endpoints[url].get("inferred", False),
                        "historical": state.endpoints[url].get("historical", False),
                        "fallback_status": fallback_status,
                    }
                    if status == 403:
                        entry["bypassed"] = url in state.bypassed
                        if url not in {e["url"] for e in state.ep_list}:
                            state.ep_list.append(entry)
                    else:
                        if url.lower().endswith(".php"):
                            state.php_list.append(entry)
                        else:
                            state.ep_list.append(entry)
                    # Removed 'and not entry["fallback"]'; always append, mark instead
        except Exception as e:
            log_err(f"Error validating {url}: {e}")

async def extract_from_json(data: Any, base: str, client: httpx.AsyncClient, state: State, depth: int = 0):
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(data, dict):
        for v in data.values():
            await extract_from_json(v, base, client, state, depth + 1)
    elif isinstance(data, list):
        for item in data:
            await extract_from_json(item, base, client, state, depth + 1)
    elif isinstance(data, str):
        for _, path, _ in ENDPOINT_REGEX.findall(data):
            ep = normalize(base, path)
            if ep and same_domain(ep, base, True):  # Allow sub for JSON extracts
                await state.add_endpoint(ep, "json-extract")

# =========================
# MAIN
# =========================
async def main(args):
    global state
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    allow_sub = args.sub_domain
    verbose = args.verbose
    enum_only = args.enum_only
    directory_focused = args.directory_focused
    max_requests = args.max_requests
    route_limit = args.route_limit
    historical = not args.no_historical

    state = State(max_requests, directory_focused, route_limit)
    state.base_netloc = urlparse(target).netloc
    state.base_domain = '.'.join(state.base_netloc.split('.')[-2:]) if len(state.base_netloc.split('.')) > 1 else state.base_netloc
    js_engine = JSAnalyzer(target, allow_sub, state)
    crawler = HTMLCrawler(target, allow_sub, js_engine, state)

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=TIMEOUT) as client:
        # Discovery Phase
        log_progress("Starting Discovery Phase...")
        await crawler.crawl(client)
        if historical:
            await historical_discover(client, target, state)

        # Analysis Phase
        log_progress("Starting Analysis Phase...")
        await analyze_endpoints(state)

        if not enum_only:
            # Validation Phase
            log_progress("Starting Validation Phase...")
            await get_home_metrics(client, target, state)
            tasks = [validate_url(client, ep, state, verbose) for ep in list(state.endpoints.keys())]
            await asyncio.gather(*tasks)

    # Output
    print("\n" + "=" * 60)
    if state.js_list:
        print(f"{Fore.CYAN}[+] JS encontrados ({len(state.js_list)}):{Style.RESET_ALL}")
        for js in sorted(set(state.js_list)):
            print(f"{Fore.YELLOW}[JS]{Style.RESET_ALL} {js}")
    if state.php_list:
        state.php_list = sorted(state.php_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints PHP:{Style.RESET_ALL}")
        for php in state.php_list:
            status_color = STATUS_COLORS.get(php["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(php["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if php["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if php["fallback"] else ""
            doubtful_str = " [DOUBTFUL]" if php["doubtful"] else ""
            inferred_str = " [INFERRED]" if php["inferred"] else ""
            historical_str = " [HISTORICAL]" if php["historical"] else ""
            fallback_status_str = f" {{FALLBACK_{php['fallback_status'].upper()}}}" if php["fallback_status"] else ""
            print(f"{Fore.MAGENTA}[PHP]{Style.RESET_ALL} {status_color}{php['url']} [{php['status']}] {class_color}({php['class']}){dynamic_str}{fallback_str}{doubtful_str}{inferred_str}{historical_str}{fallback_status_str}{Style.RESET_ALL}")
    if state.ep_list:
        state.ep_list = sorted(state.ep_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints interesantes:{Style.RESET_ALL}")
        for ep in state.ep_list:
            status_color = STATUS_COLORS.get(ep["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(ep["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if ep["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if ep["fallback"] else ""
            bypass_str = " {BYPASSED}" if ep.get("bypassed") else ""
            doubtful_str = " [DOUBTFUL]" if ep["doubtful"] else ""
            inferred_str = " [INFERRED]" if ep["inferred"] else ""
            historical_str = " [HISTORICAL]" if ep["historical"] else ""
            fallback_status_str = f" {{FALLBACK_{ep['fallback_status'].upper()}}}" if ep["fallback_status"] else ""
            print(f"{Fore.CYAN}[EP]{Style.RESET_ALL} {status_color}{ep['url']} [{ep['status']}] {class_color}({ep['class']}){dynamic_str}{fallback_str}{bypass_str}{doubtful_str}{inferred_str}{historical_str}{fallback_status_str}{Style.RESET_ALL}")
    if enum_only:
        print(f"\n{Fore.CYAN}[+] All Collected Endpoints/Routes (Unvalidated):{Style.RESET_ALL}")
        for url, data in sorted(state.endpoints.items(), key=lambda x: x[0]):
            doubtful_str = " [DOUBTFUL]" if data["doubtful"] else ""
            inferred_str = " [INFERRED]" if data["inferred"] else ""
            route_str = " [ROUTE]" if data["is_route"] else ""
            historical_str = " [HISTORICAL]" if data["historical"] else ""
            fallback_cand_str = " [FALLBACK_CANDIDATE]" if data["fallback_candidate"] else ""
            host_mismatch_str = " [HOST_MISMATCH]" if data["host_mismatch"] else ""
            print(f"{Fore.LIGHTYELLOW_EX}{url}{doubtful_str}{inferred_str}{route_str}{historical_str}{fallback_cand_str}{host_mismatch_str}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}[+] Total requests: {state.requests}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Total endpoints collected: {len(state.endpoints)}{Style.RESET_ALL}")
    if not enum_only:
        print(f"{Fore.CYAN}[+] Endpoints validados (200/401/403): {len(state.php_list) + len(state.ep_list)}{Style.RESET_ALL}")
    if state.successful_bypasses:
        print(f"\n{Fore.CYAN}[+] Successful 403 Bypasses:{Style.RESET_ALL}")
        for bypass in sorted(set(state.successful_bypasses)):
            print(Back.CYAN + Fore.BLACK + bypass + Style.RESET_ALL)

def stop_signal(sig, frame):
    global state
    if state:
        state.stop = True
    print("\n[!] Interrumpido por el usuario")
    sys.exit(0)

signal.signal(signal.SIGINT, stop_signal)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Recursive Endpoint Discovery Engine")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--sub-domain", action="store_true", help="Allow subdomains")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--wayback", action="store_true", help="Enumeration only, no validation")
    parser.add_argument("--directory-focused", action="store_true", help="Focus on directory routes")
    parser.add_argument("--no-historical",action="store_true",help="Disable historical route discovery (Wayback Machine)")
    parser.add_argument("--max-requests", type=int, default=500000, help="Max HTTP requests")
    parser.add_argument("--route-limit", type=int, default=MAX_ROUTE_LIMIT, help="Max routes to collect")
    args = parser.parse_args()
    asyncio.run(main(args))
