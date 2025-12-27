#!/usr/bin/env python3
# =========================
# Advanced Recursive Endpoint Discovery Engine - Versión Final Corregida
# =========================
import asyncio
import json
import re
import sys
import signal
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict
from typing import Set, Dict, List, Any
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
IGNORE_EXT = (
    ".jpg",".jpeg",".png",".gif",".svg",".ico",
    ".mp4",".mp3",".avi",".mov",".mkv",
    ".woff",".woff2",".ttf",".eot",".otf",".css",
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
REACT_ROUTE_KEYS = ("path", "to", "href")
REACT_ROUTE_FUNCS = ("navigate", "push", "replace", "Link", "useNavigate")
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
    "auth": 7,
    "api": 6,
    "graphql": 5,
    "debug": 4,
    "upload": 3,
    "export": 2,
    "backup": 1,
    "other": 0,
}
MAX_JS_DEPTH = 10
EXPLOIT_VALUES = ["admin", "debug", "internal", "1", "0", "-1"]
MAX_JSON_DEPTH = 5
# =========================
# ESTADO GLOBAL
# =========================
class State:
    def __init__(self, max_requests: int):
        self.max_requests = max_requests
        self.requests = 0
        self.stop = False
        self.seen_js: Set[str] = set()
        self.js_graph: Dict[str, Set[str]] = defaultdict(set)
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self.canon_to_original: Dict[str, str] = {}
        self.js_list: List[str] = []
        self.php_list: List[Dict] = []
        self.ep_list: List[Dict] = []
        self.base_netloc = ""
        self._processing_variants = set()
        self.successful_bypasses: List[str] = []
        self.home_hash: str | None = None
        self.home_length: int | None = None
        self.home_content_type: str | None = None
        self.dynamic_urls: List[str] = []
        self.bypassed: Set[str] = set()
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
    async def add_endpoint(self, url: str, source: str):
        if url.lower().endswith(IGNORE_EXT):
            return
        netloc = urlparse(url).netloc
        if netloc != self.base_netloc and not netloc.endswith("." + self.base_netloc):
            return
        canon = self.canonical_url(url)
        if canon in self.canon_to_original:
            return
        self.canon_to_original[canon] = url
        cls = self.classify(url)
        params = self.extract_params(url)
        has_params = bool(params)
        if cls == "other" and not has_params and not url.endswith((".php", ".json", ".bak")):
            return
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
            "is_dynamic": False,
            "fallback": False,
        }
        parsed = urlparse(url)
        is_dynamic = ':' in parsed.path or '{' in parsed.path or '${' in parsed.path
        if is_dynamic:
            self.endpoints[url]["is_dynamic"] = True
            self.dynamic_urls.append(url)
state: State | None = None
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
def is_fallback_response(original_url: str, r: httpx.Response, home_hash, home_length, home_content_type) -> bool:
    final_url = str(r.url)

    # Redirect silencioso al home/login
    if final_url != original_url:
        if urlparse(final_url).path in ("/", "/login", "/login/"):
            return True

    content_type = r.headers.get("content-type", "")
    if "text/html" not in content_type:
        return False

    body = r.text.lower()

    # SPA redirects comunes
    if any(x in body for x in [
        "<div id=\"root\"",
        "<div id=\"app\"",
        "window.__initial_state__",
        "react-dom",
        "angular",
        "vue"
    ]):
        # comparación estructural ligera
        if home_length and abs(len(r.content) - home_length) < 500:
            return True

    # JS redirect
    if re.search(r'window\.location|history\.pushstate', body, re.I):
        return True

    # Igualdad fuerte
    if home_hash:
        this_hash = hashlib.md5(r.content).hexdigest()
        if this_hash == home_hash:
            return True

    return False

# =========================
# HTTP VALIDATION
# =========================
async def get_home_fingerprint(client: httpx.AsyncClient, home_url: str):
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
        except:
            pass
async def check_if_fallback(client: httpx.AsyncClient, url: str) -> bool:
    async with state.semaphore:
        if not state.can_request():
            return False
        try:
            state.register_request(url)
            r_head = await client.head(url, timeout=TIMEOUT)
            if r_head.status_code in (301, 302, 303, 307, 308):
                location = r_head.headers.get("location", "")
                parsed_loc = urlparse(location)
                if parsed_loc.path in ("/", "/login", "/login/"):
                    return True
        except:
            pass
        try:
            state.register_request(url)
            r = await client.get(url, timeout=TIMEOUT)
            status = r.status_code
            if status != 200:
                return False
            return is_fallback_response(url, r, state.home_hash, state.home_length, state.home_content_type)
        except:
            return False
async def process_dynamic_urls(client: httpx.AsyncClient):
    for dyn_url in list(set(state.dynamic_urls)):
        if dyn_url not in state.endpoints:
            continue
        source = state.endpoints[dyn_url]["source"]
        parsed = urlparse(dyn_url)
        clean_path = re.sub(r'/:[^/]+|/\{[^}]+\}|/\$\{[^}]+\}', '', parsed.path)
        clean_path = re.sub(r'//+', '/', clean_path)
        clean_url = parsed._replace(path=clean_path, query='', fragment='').geturl()
        is_fallback = await check_if_fallback(client, clean_url)
        if is_fallback:
            state.endpoints[dyn_url]["fallback"] = True
            continue  # NO seguir probando variantes
        else:
            await state.add_endpoint(clean_url, source + "-clean")

        # Solo generar /test si NO es fallback
        if not clean_path.lower().endswith(('/test', '/debug', '/demo', '/example')):
            test_path = clean_path.rstrip('/') + '/test'
            test_url = parsed._replace(path=test_path, query='', fragment='').geturl()
            await state.add_endpoint(test_url, source + "-test")

            dyn_regex = re.compile(r'/(:[^/]+|\{[^}]+\}|\$\{[^}]+\})')
            for val in EXPLOIT_VALUES:
                var_path = dyn_regex.sub(lambda m: f'/{val}', parsed.path)
                var_path = re.sub(r'//+', '/', var_path)
                var_url = parsed._replace(path=var_path, query='', fragment='').geturl()
                if var_url != dyn_url:
                    await state.add_endpoint(var_url, source + "-variant")
async def try_bypasses(client: httpx.AsyncClient, url: str, original_response: httpx.Response):
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
async def validate_url(client: httpx.AsyncClient, url: str):
    global verbose
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
                if status in (200, 403) and "text/html" in state.endpoints[url]["content_type"]:
                    fallback = False
                    fallback = is_fallback_response(url, r, state.home_hash, state.home_length, state.home_content_type)
                    if fallback:
                        state.endpoints[url]["fallback"] = True
                if verbose:
                    log_ep(f"{url} [{status}] ({cls})", status=status, cls=cls)
                if "application/json" in state.endpoints[url]["content_type"]:
                    try:
                        data = r.json()
                        await extract_from_json(data, url, client)
                    except:
                        pass
                if status == 403:
                    await try_bypasses(client, url, r)
                if url.endswith((".js", ".json", ".php", ".xml", ".txt", ".config")):
                    for ext in [".bak", ".old", "~", ".swp", ".txt", ".log", ".config", ".ini", ".yaml", ".yml", ".toml", ".env", ".backup"]:
                        await validate_url(client, url + ext)
                if status in (200, 401, 403):
                    entry = {
                        "url": url,
                        "status": status,
                        "class": cls,
                        "priority": CLASS_PRIORITY.get(cls, 0),
                        "is_dynamic": state.endpoints[url].get("is_dynamic", False),
                        "fallback": state.endpoints[url].get("fallback", False)
                    }
                    if status == 403:
                        entry["bypassed"] = url in state.bypassed
                        if url not in {e["url"] for e in state.ep_list}:
                            state.ep_list.append(entry)
                    elif not entry["fallback"]:
                        if url.lower().endswith(".php"):
                            state.php_list.append(entry)
                        else:
                            state.ep_list.append(entry)
        except:
            pass
async def extract_from_json(data: Any, base: str, client: httpx.AsyncClient, depth: int = 0):
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(data, dict):
        for v in data.values():
            await extract_from_json(v, base, client, depth + 1)
    elif isinstance(data, list):
        for item in data:
            await extract_from_json(item, base, client, depth + 1)
    elif isinstance(data, str):
        for _, path, _ in ENDPOINT_REGEX.findall(data):
            ep = normalize(base, path)
            if ep:
                await state.add_endpoint(ep, "json-extract")
                await validate_url(client, ep)
# =========================
# JS ANALYZER
# =========================
class JSAnalyzer:
    def __init__(self, base_url: str, allow_subdomains: bool):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js_depth: Dict[str, int] = {}
    async def analyze_js(self, client: httpx.AsyncClient, url: str, depth: int = 0):
        if url in state.seen_js or depth > MAX_JS_DEPTH:
            return
        # Solo añadir si es un archivo .js real
        if url.lower().endswith(".js") and "://" in url:
            state.js_list.append(url)
            log_js(url)
        state.seen_js.add(url)
        try:
            state.register_request(url)
            r = await client.get(url, timeout=TIMEOUT)
            code = r.text
            for _, path, _ in ENDPOINT_REGEX.findall(code):
                ep = normalize(url, path)
                if ep:
                    await state.add_endpoint(ep, "js-regex")
            try:
                tree = esprima.parseScript(code, tolerant=True)
                async def walk(node):
                    if isinstance(node, dict):
                        if node.get("type") == "Literal" and isinstance(node.get("value"), str):
                            val = node["value"]
                            if val.startswith("/"):
                                ep = normalize(url, val)
                                if ep:
                                    await state.add_endpoint(ep, "js-ast")
                        for v in node.values():
                            if isinstance(v, (dict, list)):
                                await walk(v)
                    elif isinstance(node, list):
                        for i in node:
                            await walk(i)
                await walk(tree)
            except:
                pass
            if url.endswith(".js"):
                await self.analyze_sourcemap(client, url)
            import_rx = re.compile(r'import\((["\'`])(.+?)\1\)', re.I)
            for _, imp_path in import_rx.findall(code):
                imp_url = normalize(url, imp_path)
                if imp_url and same_domain(imp_url, self.base, self.allow_subdomains):
                    await self.analyze_js(client, imp_url, depth + 1)
        except:
            pass
    async def analyze_sourcemap(self, client: httpx.AsyncClient, js_url: str):
        map_url = js_url + ".map"
        try:
            state.register_request(map_url)
            r = await client.get(map_url, timeout=TIMEOUT)
            if r.status_code == 200:
                sm = r.json()
                for orig in sm.get("sources", []):
                    clean_path = re.sub(r'^(webpack:///\.?/|~|@|\?\?)/?', '', orig)
                    ep = normalize(js_url, clean_path)
                    if ep and not ignored(ep) and not is_noise_js(ep):
                        await state.add_endpoint(ep, "sourcemap-path")
        except:
            pass
# =========================
# HTML CRAWLER
# =========================
class HTMLCrawler:
    def __init__(self, base_url: str, allow_subdomains: bool, js_engine: JSAnalyzer):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js = js_engine
        self.visited: Set[str] = set()
        self.queue: List[str] = [base_url]
    async def crawl(self, client: httpx.AsyncClient):
        while self.queue and len(self.visited) < MAX_HTML_PAGES and state.can_request():
            url = self.queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            log_info(f"HTML {url} ({len(self.visited)}/{MAX_HTML_PAGES})")
            try:
                state.register_request(url)
                r = await client.get(url, timeout=TIMEOUT)
                if "text/html" not in r.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                for s in soup.find_all("script", src=True):
                    js_url = normalize(url, s["src"])
                    if js_url and same_domain(js_url, self.base, self.allow_subdomains):
                        if not ignored(js_url) and not is_noise_js(js_url):
                            await self.js.analyze_js(client, js_url)
                for tag in soup.find_all(["a", "form"]):
                    attr = tag.get("href") or tag.get("action")
                    if attr:
                        nxt = normalize(url, attr)
                        if nxt and same_domain(nxt, self.base, self.allow_subdomains) and not ignored(nxt):
                            await state.add_endpoint(nxt, "html")
                            if len(self.visited) < MAX_HTML_PAGES:
                                self.queue.append(nxt)
            except:
                continue
# =========================
# MAIN
# =========================
async def main():
    global state, verbose
    if len(sys.argv) < 2:
        print("Uso: python3 endPOINDV2.py <url> [--sub-domain] [--verbose]")
        sys.exit(1)
    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    allow_sub = "--sub-domain" in sys.argv
    verbose = "--verbose" in sys.argv
    state = State(500000)
    state.base_netloc = urlparse(target).netloc
    js_engine = JSAnalyzer(target, allow_sub)
    crawler = HTMLCrawler(target, allow_sub, js_engine)
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=TIMEOUT) as client:
        await get_home_fingerprint(client, target)
        await crawler.crawl(client)
        await process_dynamic_urls(client)
        log_progress(f"Validando {len(state.endpoints)} endpoints...")
        tasks = [validate_url(client, ep) for ep in list(state.endpoints.keys())]
        await asyncio.gather(*tasks)
    # === SALIDA FINAL CON COLORES Y SIN SECCIONES VACÍAS ===
    print("\n" + "="*60)
    # JS (solo archivos reales .js)
    if state.js_list:
        print(f"{Fore.CYAN}[+] JS encontrados ({len(state.js_list)}):{Style.RESET_ALL}")
        for js in sorted(set(state.js_list)):
            print(f"{Fore.YELLOW}[JS]{Style.RESET_ALL} {js}")
    # PHP
    if state.php_list:
        state.php_list = sorted(state.php_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints PHP:{Style.RESET_ALL}")
        for php in state.php_list:
            status_color = STATUS_COLORS.get(php["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(php["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if php["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if php["fallback"] else ""
            print(f"{Fore.MAGENTA}[PHP]{Style.RESET_ALL} {status_color}{php['url']} [{php['status']}] {class_color}({php['class']}){dynamic_str}{fallback_str}{Style.RESET_ALL}")
    # Endpoints interesantes
    if state.ep_list:
        state.ep_list = sorted(state.ep_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints interesantes:{Style.RESET_ALL}")
        for ep in state.ep_list:
            status_color = STATUS_COLORS.get(ep["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(ep["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if ep["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if ep["fallback"] else ""
            bypass_str = " {BYPASSED}" if ep.get("bypassed") else ""
            print(f"{Fore.CYAN}[EP]{Style.RESET_ALL} {status_color}{ep['url']} [{ep['status']}] {class_color}({ep['class']}){dynamic_str}{fallback_str}{bypass_str}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[+] Total requests: {state.requests}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Endpoints validados (200/401/403): {len(state.php_list) + len(state.ep_list)}{Style.RESET_ALL}")
    if state.successful_bypasses:
        print(f"\n{Fore.CYAN}[+] Successful 403 Bypasses:{Style.RESET_ALL}")
        for bypass in sorted(set(state.successful_bypasses)):
            print(Back.CYAN + Fore.BLACK + bypass + Style.RESET_ALL)
def stop_signal(sig, frame):
    if state:
        state.stop = True
    print("\n[!] Interrumpido por el usuario")
    sys.exit(0)
signal.signal(signal.SIGINT, stop_signal)
if __name__ == "__main__":
    asyncio.run(main())
