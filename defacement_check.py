#!/usr/bin/env python3

import asyncio
import hashlib
import json
import os
import re
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

import imagehash
from bs4 import BeautifulSoup
from PIL import Image, ImageDraw, ImageFont
from playwright.async_api import async_playwright
from dotenv import load_dotenv


# ============================================================
# LOAD CONFIGURATION
# ============================================================

load_dotenv()


# ============================================================
# FILE CONFIGURATION
# ============================================================

DOMAINS_FILE = Path("domains.txt")
DATA_DIR = Path("website_data")
BASELINES_DIR = DATA_DIR / "baselines"
BASELINE_SCREENSHOTS_DIR = DATA_DIR / "baseline_screenshots"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
COMPARISONS_DIR = DATA_DIR / "comparisons"
EVIDENCE_DIR = DATA_DIR / "evidence"
ALL_RESULTS_FILE = DATA_DIR / "scan_results.json"
SUSPICIOUS_FILE = DATA_DIR / "suspicious.json"
LIKELY_DEFACED_FILE = DATA_DIR / "likely_defaced.json"


# ============================================================
# DETECTION CONFIGURATION
# ============================================================

ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "60"))
DEFACEMENT_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "300"))

# How many times to retry a failed scan before giving up
MAX_SCAN_RETRIES = int(os.getenv("MAX_SCAN_RETRIES", "3"))
# Seconds to wait between retries
RETRY_DELAY_SECONDS = int(os.getenv("RETRY_DELAY_SECONDS", "15"))

# Site types affect scoring weights.
# Set in domains.txt as: https://example.com #type:news
# Types: static (default), news, ecommerce
SITE_TYPE_DEFAULT = "static"


# ============================================================
# TRUSTED DOMAIN WHITELIST
# These domains are common on legitimate sites and do NOT
# contribute to the external domain score.
# ============================================================

TRUSTED_DOMAINS = {
    # Google analytics / ads
    "google.com", "www.google.com", "google.am", "www.google.am",
    "googleapis.com", "ajax.googleapis.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "maps.googleapis.com",
    "analytics.google.com", "tagmanager.google.com",
    "googletagmanager.com", "www.googletagmanager.com",
    "googletagservices.com", "googlesyndication.com",
    "doubleclick.net", "stats.g.doubleclick.net", "ad.doubleclick.net",
    "googleadservices.com", "google-analytics.com",
    "www.google-analytics.com", "ssl.google-analytics.com",
    # Cloudflare
    "cloudflare.com", "cdnjs.cloudflare.com",
    "static.cloudflareinsights.com", "cloudflareinsights.com",
    # Facebook / Meta
    "facebook.com", "www.facebook.com", "connect.facebook.net",
    "facebook.net", "fbcdn.net", "staticxx.facebook.com",
    # Twitter / X
    "twitter.com", "platform.twitter.com", "syndication.twitter.com",
    "t.co",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "bing.com",
    "clarity.ms", "c.bing.com",
    # CDNs
    "jsdelivr.net", "cdn.jsdelivr.net",
    "unpkg.com",
    "bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "jquery.com", "code.jquery.com",
    "akamaihd.net", "akamai.net", "akamaized.net",
    "fastly.net", "cloudfront.net",
    # YouTube
    "youtube.com", "www.youtube.com", "youtu.be",
    "youtube-nocookie.com", "www.youtube-nocookie.com",
    "ytimg.com", "i.ytimg.com", "s.ytimg.com",
    # WordPress
    "wordpress.com", "wp.com", "s.w.org", "i0.wp.com", "i1.wp.com",
    # Analytics / monitoring
    "hotjar.com", "static.hotjar.com", "script.hotjar.com",
    "yandex.ru", "mc.yandex.ru",
    "newrelic.com", "js-agent.newrelic.com",
    "segment.com", "cdn.segment.com",
    "mixpanel.com", "cdn.mxpnl.com",
    "intercom.io", "widget.intercom.io",
    # Social
    "linkedin.com", "platform.linkedin.com",
    "instagram.com", "www.instagram.com",
    # Maps
    "openstreetmap.org", "tile.openstreetmap.org",
    # Captcha
    "recaptcha.net", "www.recaptcha.net", "hcaptcha.com",
    # Payments
    "stripe.com", "js.stripe.com",
    "paypal.com", "www.paypalobjects.com",
    # Google static assets
    "gstatic.com", "www.gstatic.com",
    "translate.googleapis.com", "translate.google.com",
    "translate-pa.googleapis.com",
    # Social sharing widgets
    "addtoany.com", "static.addtoany.com",
    "sharethis.com", "platform.sharethis.com",
    "addthis.com", "s7.addthis.com",
    # Common iframe embeds
    "maps.google.com", "www.google.com",
    "player.vimeo.com", "vimeo.com",
    "open.spotify.com",
    "w.soundcloud.com",
    # Armenian gov / common regional domains
    "gov.am", "e-gov.am",
    # Live chat widgets — legitimate SaaS tools
    "jivosite.com", "code.jivosite.com",
    "tawk.to", "embed.tawk.to",
    "openwidget.com", "cdn.openwidget.com",
    "purechat.com", "app.purechat.com",
    "manychat.com", "widget.manychat.com",
    "tidio.com", "widget.tidio.com",
    "zendesk.com", "static.zdassets.com",
    "freshdesk.com", "freshworks.com",
    "intercom.com", "js.intercomcdn.com",
    "drift.com", "js.driftt.com",
    "crisp.chat", "client.crisp.chat",
    # Marketing / ad platforms
    "snap.licdn.com",
    "scarabresearch.com", "cdn.scarabresearch.com", "static.scarabresearch.com",
    "eventable.com", "plugins.eventable.com",
    "eskimi.com", "dsp-media.eskimi.com",
    "mccdn.me",
    "jotfor.ms", "cdn.jotfor.ms",
    # Developer CDNs — clearly not malicious
    "datatables.net", "cdn.datatables.net",
    "d3js.org",
    "jsdelivr.net", "cdn.jsdelivr.net",
    "cdnjs.com", "cdnjs.cloudflare.com",
    "rawgit.com", "rawcdn.githack.com",
    # Analytics
    "yandex.com", "mc.yandex.com",
    "amazonaws.com",
    # Weather widgets
    "gismeteo.ua", "www.gismeteo.ua",
    "weather.com",
    # Map / geo
    "openstreetmap.org", "tile.openstreetmap.org",
    "leafletjs.com",
}


def is_trusted_domain(domain: str) -> bool:
    """
    Returns True if domain or any of its parent domains are in the whitelist.
    e.g. 'stats.g.doubleclick.net' matches 'doubleclick.net'
    """
    domain = domain.lower()
    if domain in TRUSTED_DOMAINS:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in TRUSTED_DOMAINS:
            return True
    return False


def _root_domain(domain: str) -> str:
    """
    Returns the registrable root domain (last two labels).
    'sub.example.com' -> 'example.com'
    'example.am'      -> 'example.am'
    """
    domain = domain.lower().rstrip(".")
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


# ============================================================
# BROWSER CONFIGURATION
# ============================================================

VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 1200
PAGE_TIMEOUT = 60000
POST_LOAD_WAIT = 2000


# ============================================================
# EMAIL CONFIGURATION
# ============================================================

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"


# ============================================================
# LANGUAGE / SCRIPT DETECTION
# ============================================================

def detect_script(text: str) -> str:
    """
    Returns dominant Unicode script family in text.
    latin | cyrillic | arabic | armenian | chinese | mixed | unknown
    """
    if not text:
        return "unknown"

    counts = {
        "latin":     0,
        "cyrillic":  0,
        "arabic":    0,
        "armenian":  0,
        "chinese":   0,
    }

    for ch in text:
        cp = ord(ch)
        if 0x0041 <= cp <= 0x024F:
            counts["latin"] += 1
        elif 0x0400 <= cp <= 0x04FF:
            counts["cyrillic"] += 1
        elif 0x0600 <= cp <= 0x06FF:
            counts["arabic"] += 1
        elif 0x0530 <= cp <= 0x058F:
            counts["armenian"] += 1
        elif 0x4E00 <= cp <= 0x9FFF:
            counts["chinese"] += 1

    total = sum(counts.values())
    if total == 0:
        return "unknown"

    dominant = max(counts, key=counts.get)
    dominant_ratio = counts[dominant] / total

    if dominant_ratio >= 0.6:
        return dominant
    return "mixed"


# ============================================================
# DIRECTORY SETUP
# ============================================================

def create_directories():
    for directory in [
        DATA_DIR, BASELINES_DIR, BASELINE_SCREENSHOTS_DIR,
        SCREENSHOTS_DIR, COMPARISONS_DIR, EVIDENCE_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# URL / DOMAIN HELPERS
# ============================================================

def safe_filename(url: str) -> str:
    parsed = urlparse(url)
    value = parsed.netloc + parsed.path
    if not value:
        value = url
    value = re.sub(r"[^a-zA-Z0-9._-]", "_", value).strip("_")
    return (value or "website")[:200]


def load_domains():
    """
    Read domains.txt fresh on every call.
    Supports optional site-type tags:
        https://bbc.com  #type:news
        https://shop.example.com  #type:ecommerce
        https://static.example.com  #type:static  (default)
    Returns list of (url, site_type) tuples.
    """
    if not DOMAINS_FILE.exists():
        print(f"[WARNING] {DOMAINS_FILE} does not exist — skipping cycle.")
        return []

    seen = {}
    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Strip inline comment, parse site type
            site_type = SITE_TYPE_DEFAULT
            if "#" in line:
                parts = line.split("#", 1)
                line = parts[0].strip()
                comment = parts[1].strip()
                m = re.search(r"type:(\w+)", comment)
                if m:
                    site_type = m.group(1).lower()

            if not line:
                continue
            if not line.startswith(("http://", "https://")):
                line = "https://" + line

            if line not in seen:
                seen[line] = site_type

    return [(url, stype) for url, stype in seen.items()]


# ============================================================
# DOM NORMALIZATION
# ============================================================

def normalize_dom(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    allowed = {"id", "class", "role", "name", "type"}
    for tag in soup.find_all(True):
        tag.attrs = {k: v for k, v in tag.attrs.items() if k in allowed}
    for node in soup.find_all(string=True):
        node.replace_with("")
    return re.sub(r"\s+", " ", str(soup)).strip()


def dom_hash(html: str) -> str:
    return hashlib.sha256(normalize_dom(html).encode()).hexdigest()


# ============================================================
# TEXT
# ============================================================

def normalize_visible_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def text_hash(text: str) -> str:
    return hashlib.sha256(normalize_visible_text(text.lower()).encode()).hexdigest()


# ============================================================
# TITLE HELPERS
# ============================================================

def title_brand_prefix(title: str) -> str:
    """
    Extract the brand/site-name part from a title.
    'BBC News | World' -> 'bbc news'
    'ArmenTech - Software' -> 'armentech'
    """
    for sep in ["|", "—", "–", "-", ":"]:
        if sep in title:
            return title.split(sep)[0].strip().lower()
    return title.strip().lower()


# ============================================================
# EXTERNAL DOMAINS
# ============================================================

def get_external_domains(page_url: str, resources: list) -> list:
    page_domain = urlparse(page_url).netloc.lower()
    domains = set()
    for resource in resources:
        try:
            domain = urlparse(resource).netloc.lower()
            if domain and domain != page_domain:
                domains.add(domain)
        except Exception:
            continue
    return sorted(domains)


# ============================================================
# SCREENSHOT HASH
# ============================================================

def calculate_phash(screenshot_path) -> str:
    return str(imagehash.phash(Image.open(screenshot_path)))


def hamming_distance(hash1: str, hash2: str) -> int:
    return bin(int(hash1, 16) ^ int(hash2, 16)).count("1")


# ============================================================
# DOMINANT COLOR EXTRACTION
# ============================================================

def get_dominant_colors(image_path, n=5) -> list:
    """
    Returns the top-n most frequent colors (quantized to 32-step palette)
    as hex strings. Used to detect brand color scheme changes.
    """
    try:
        img = Image.open(image_path).convert("RGB")
        # Resize for speed
        img = img.resize((200, 150))
        # Quantize colors
        pixels = list(img.getdata())
        quantized = [
            (r // 32 * 32, g // 32 * 32, b // 32 * 32)
            for r, g, b in pixels
        ]
        freq = {}
        for px in quantized:
            freq[px] = freq.get(px, 0) + 1
        top = sorted(freq, key=freq.get, reverse=True)[:n]
        return ["#{:02x}{:02x}{:02x}".format(*c) for c in top]
    except Exception:
        return []


def color_scheme_distance(colors1: list, colors2: list) -> float:
    """
    Returns 0.0 (identical) to 1.0 (completely different) based on
    overlap of dominant color palettes.
    """
    if not colors1 or not colors2:
        return 0.0
    set1, set2 = set(colors1), set(colors2)
    overlap = len(set1 & set2)
    union = len(set1 | set2)
    return 1.0 - (overlap / union) if union else 0.0


# ============================================================
# PAGE SCAN
# ============================================================

async def scan_website(browser, url: str) -> dict:

    page = await browser.new_page(
        viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT}
    )

    filename = safe_filename(url)
    current_screenshot = SCREENSHOTS_DIR / f"{filename}.png"

    try:
        print(f"[SCAN] {url}")

        response = await page.goto(
            url, wait_until="networkidle", timeout=PAGE_TIMEOUT
        )
        await page.wait_for_timeout(POST_LOAD_WAIT)

        final_url = page.url
        html = await page.content()
        title = await page.title()
        status_code = response.status if response else None

        # Screenshot
        await page.screenshot(path=str(current_screenshot), full_page=True)
        screenshot_hash = calculate_phash(current_screenshot)
        dominant_colors = get_dominant_colors(current_screenshot)

        # Identity elements
        header_count = await page.locator("header").count()
        nav_count = await page.locator("nav").count()
        footer_count = await page.locator("footer").count()
        logo_count = await page.locator(
            "img[alt*='logo' i], [class*='logo' i], [id*='logo' i]"
        ).count()
        form_count = await page.locator("form").count()
        iframe_count = await page.locator("iframe").count()

        # Visible text + language
        visible_text = await page.locator("body").inner_text(timeout=10000)
        visible_text = normalize_visible_text(visible_text)
        dominant_script = detect_script(visible_text)

        # Resource URLs (for external domain tracking)
        resource_urls = await page.evaluate("""
            () => {
                const urls = new Set();
                performance.getEntriesByType("resource")
                    .forEach(e => urls.add(e.name));
                return [...urls];
            }
        """)
        external_domains = get_external_domains(final_url, resource_urls)

        # Script src domains — separate from general resources
        script_src_domains = await page.evaluate("""
            () => {
                const domains = new Set();
                document.querySelectorAll("script[src]").forEach(s => {
                    try {
                        const u = new URL(s.src);
                        domains.add(u.hostname.toLowerCase());
                    } catch(e) {}
                });
                return [...domains];
            }
        """)
        page_domain = urlparse(final_url).netloc.lower()
        script_src_domains = [d for d in script_src_domains if d != page_domain]

        # Links
        links = await page.evaluate("""
            () => Array.from(document.querySelectorAll("a")).map(a => ({
                text: (a.innerText || "").trim(),
                href: a.href
            }))
        """)

        # Nav link domains
        nav_link_domains = await page.evaluate("""
            () => {
                const domains = new Set();
                document.querySelectorAll("nav a[href]").forEach(a => {
                    try {
                        const u = new URL(a.href);
                        domains.add(u.hostname.toLowerCase());
                    } catch(e) {}
                });
                return [...domains];
            }
        """)

        # Forms — with action domain tracking
        forms = await page.evaluate("""
            () => Array.from(document.querySelectorAll("form")).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.querySelectorAll("input")).map(i => ({
                    type: i.type,
                    name: i.name
                }))
            }))
        """)

        # Form action domains (external only)
        form_action_domains = []
        for form in forms:
            action = form.get("action", "") or ""
            if action.startswith("http"):
                try:
                    d = urlparse(action).netloc.lower()
                    if d and d != page_domain:
                        form_action_domains.append(d)
                except Exception:
                    pass

        # iframe src domains
        iframe_src_domains = await page.evaluate("""
            () => {
                const domains = new Set();
                document.querySelectorAll("iframe[src]").forEach(f => {
                    try {
                        const u = new URL(f.src);
                        domains.add(u.hostname.toLowerCase());
                    } catch(e) {}
                });
                return [...domains];
            }
        """)

        # Canonical URL
        canonical_url = await page.evaluate("""
            () => {
                const el = document.querySelector("link[rel='canonical']");
                return el ? el.href : null;
            }
        """)

        # Meta description
        meta_description = await page.evaluate("""
            () => {
                const el = document.querySelector("meta[name='description']");
                return el ? el.content : "";
            }
        """)

        # Robots meta
        robots_meta = await page.evaluate("""
            () => {
                const el = document.querySelector("meta[name='robots']");
                return el ? el.content.toLowerCase() : "";
            }
        """)

        # Large fixed overlays
        large_overlays = await page.evaluate("""
            () => {
                const results = [];
                const vw = window.innerWidth;
                const vh = window.innerHeight;
                for (const el of document.querySelectorAll("*")) {
                    const style = getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    const wp = rect.width / vw * 100;
                    const hp = rect.height / vh * 100;
                    if (style.position === "fixed" && wp >= 50 && hp >= 50) {
                        results.push({
                            tag: el.tagName,
                            id: el.id,
                            className: String(el.className),
                            width_percent: Math.round(wp),
                            height_percent: Math.round(hp),
                            z_index: style.zIndex
                        });
                    }
                }
                return results;
            }
        """)

        # DOM structure
        structure = await page.evaluate("""
            () => {
                function build(el, depth = 0) {
                    if (depth > 8) return null;
                    const r = { tag: el.tagName.toLowerCase(), children: [] };
                    for (const child of el.children) {
                        const n = build(child, depth + 1);
                        if (n) r.children.push(n);
                    }
                    return r;
                }
                return build(document.documentElement);
            }
        """)

        return {
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_code": status_code,
            "final_url": final_url,
            "title": title,
            "title_prefix": title_brand_prefix(title),
            "dom_hash": dom_hash(html),
            "text_hash": text_hash(visible_text),
            "screenshot_hash": screenshot_hash,
            "dominant_colors": dominant_colors,
            "dominant_script": dominant_script,
            "identity": {
                "header": header_count > 0,
                "nav": nav_count > 0,
                "footer": footer_count > 0,
                "logo": logo_count > 0,
                "forms": form_count,
                "iframes": iframe_count,
            },
            "external_domains": external_domains,
            "script_src_domains": script_src_domains,
            "nav_link_domains": sorted(set(nav_link_domains)),
            "form_action_domains": form_action_domains,
            "iframe_src_domains": sorted(set(iframe_src_domains)),
            "canonical_url": canonical_url,
            "meta_description": meta_description,
            "robots_meta": robots_meta,
            "links": links,
            "forms": forms,
            "large_overlays": large_overlays,
            "structure": structure,
            "screenshot": str(current_screenshot),
        }

    except Exception as e:
        print(f"[ERROR] {url}: {e}")
        return {
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }
    finally:
        await page.close()


# ============================================================
# BASELINE
# ============================================================

def baseline_file(url: str) -> Path:
    return BASELINES_DIR / f"{safe_filename(url)}.json"


def baseline_screenshot_file(url: str) -> Path:
    return BASELINE_SCREENSHOTS_DIR / f"{safe_filename(url)}.png"


def load_baseline(url: str) -> dict | None:
    path = baseline_file(url)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_baseline(url: str, snapshot: dict):
    with open(baseline_file(url), "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
    source = Path(snapshot["screenshot"])
    dest = baseline_screenshot_file(url)
    if source.exists():
        with Image.open(source) as img:
            img.convert("RGB").save(dest)


# ============================================================
# COMPARISON IMAGE
# ============================================================

def create_comparison_image(url, baseline_path, current_path, confidence, verdict):

    if not baseline_path.exists() or not current_path.exists():
        return None

    try:
        baseline = Image.open(baseline_path).convert("RGB")
        current = Image.open(current_path).convert("RGB")

        width = max(baseline.width, current.width)
        height = max(baseline.height, current.height)

        def pad(img):
            if img.width == width and img.height == height:
                return img
            canvas = Image.new("RGB", (width, height), "white")
            canvas.paste(img, (0, 0))
            return canvas

        baseline = pad(baseline)
        current = pad(current)

        header_h = 100
        comp = Image.new("RGB", (width * 2, height + header_h), "white")
        comp.paste(baseline, (0, header_h))
        comp.paste(current, (width, header_h))

        draw = ImageDraw.Draw(comp)
        try:
            font = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28
            )
            small = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20
            )
        except Exception:
            font = small = ImageFont.load_default()

        draw.text((20, 15), "INITIAL BASELINE", fill="black", font=font)
        draw.text((width + 20, 15), "LATEST SCAN", fill="black", font=font)
        draw.text((20, 58), f"Website: {url}", fill="black", font=small)
        draw.text((width + 20, 58), f"{confidence}% - {verdict}", fill="black", font=small)

        out = COMPARISONS_DIR / f"{safe_filename(url)}_comparison.png"
        comp.save(out, format="PNG")
        print(f"[COMPARISON] Created: {out} ({out.stat().st_size / 1024:.1f} KB)")
        return out

    except Exception as e:
        print(f"[ERROR] Comparison image: {e}")
        return None


# ============================================================
# DEFACEMENT ANALYSIS
# ============================================================

def analyze(current: dict, baseline: dict, site_type: str = "static") -> dict:

    if "error" in current:
        return {
            "confidence_percent": 0,
            "raw_score": 0,
            "verdict": "SCAN_ERROR",
            "likely_defaced": False,
            "suspicious": False,
            "findings": [],
        }

    score = 0
    findings = []

    # Site-type visual multiplier:
    # news/ecommerce sites change visually all the time → lower visual weight
    # static sites almost never change → higher visual weight
    visual_multiplier = {
        "static":    1.0,
        "news":      0.3,
        "ecommerce": 0.5,
    }.get(site_type, 1.0)

    def add(signal, severity, points, details):
        nonlocal score
        score += points
        findings.append({
            "signal": signal,
            "severity": severity,
            "points": points,
            "details": details,
        })

    # ----------------------------------------------------------
    # 1. SERVER ERROR
    # ----------------------------------------------------------
    status = current.get("status_code")
    if status and status >= 500:
        add("SERVER_ERROR", "LOW", 10, f"HTTP {status}")

    # ----------------------------------------------------------
    # 2. UNEXPECTED DOMAIN REDIRECT
    # ----------------------------------------------------------
    cur_domain = urlparse(current["final_url"]).netloc.lower()
    base_domain = urlparse(baseline["final_url"]).netloc.lower()
    if cur_domain != base_domain:
        add("UNEXPECTED_DOMAIN_REDIRECT", "CRITICAL", 100,
            f"{base_domain} -> {cur_domain}")

    # ----------------------------------------------------------
    # 3. IDENTITY LOSS (header / nav / footer / logo)
    # ----------------------------------------------------------
    identity_lost = []
    for el in ("header", "nav", "footer", "logo"):
        if baseline.get("identity", {}).get(el) and \
           not current.get("identity", {}).get(el):
            identity_lost.append(el)

    if identity_lost:
        pts = min(len(identity_lost) * 10, 30)
        add("IDENTITY_LOSS", "HIGH", pts, "Missing: " + ", ".join(identity_lost))

    if len(identity_lost) >= 2:
        add("MULTIPLE_IDENTITY_ELEMENTS_LOST", "HIGH", 15,
            f"{len(identity_lost)} identity elements disappeared")

    # ----------------------------------------------------------
    # 4. NEW IFRAMES
    # ----------------------------------------------------------
    old_iframes = baseline.get("identity", {}).get("iframes", 0)
    new_iframes = current.get("identity", {}).get("iframes", 0)
    if new_iframes > old_iframes:
        pts = min((new_iframes - old_iframes) * 5, 15)
        add("NEW_IFRAME", "MEDIUM", pts, f"{old_iframes} -> {new_iframes}")

    # ----------------------------------------------------------
    # 5. IFRAME SRC DOMAIN (where iframes point)
    # Google Maps, Facebook widgets, YouTube embeds are trusted.
    # ----------------------------------------------------------
    old_iframe_domains = set(baseline.get("iframe_src_domains", []))
    new_iframe_domains = set(current.get("iframe_src_domains", []))
    new_ext_iframe_raw = new_iframe_domains - old_iframe_domains
    page_root_domain = _root_domain(urlparse(current["final_url"]).netloc.lower())
    new_ext_iframe_domains = {
        d for d in new_ext_iframe_raw
        if d  # skip empty strings
        and not is_trusted_domain(d)
        and _root_domain(d) != page_root_domain
    }
    if new_ext_iframe_domains:
        pts = min(len(new_ext_iframe_domains) * 10, 15)
        add("NEW_IFRAME_EXTERNAL_SRC", "HIGH", pts,
            sorted(new_ext_iframe_domains))

    # ----------------------------------------------------------
    # 6. LARGE FIXED OVERLAY
    # ----------------------------------------------------------
    old_overlays = len(baseline.get("large_overlays", []))
    new_overlays = len(current.get("large_overlays", []))
    if new_overlays > old_overlays and new_overlays > 0:
        add("LARGE_OVERLAY", "HIGH", 15, f"{old_overlays} -> {new_overlays}")

    # ----------------------------------------------------------
    # 7. VISUAL CHANGE (pHash) — weighted by site type
    # ----------------------------------------------------------
    visual_distance = hamming_distance(
        current["screenshot_hash"], baseline["screenshot_hash"]
    )

    if visual_distance >= 35:
        pts = int(15 * visual_multiplier)
        add("MAJOR_VISUAL_CHANGE", "HIGH", pts, f"pHash distance: {visual_distance}")
    elif visual_distance >= 20:
        pts = int(10 * visual_multiplier)
        add("MODERATE_VISUAL_CHANGE", "MEDIUM", pts, f"pHash distance: {visual_distance}")
    elif visual_distance >= 10:
        pts = int(10 * visual_multiplier)
        add("MINOR_VISUAL_CHANGE", "LOW", pts, f"pHash distance: {visual_distance}")

    # ----------------------------------------------------------
    # 8. COLOR SCHEME CHANGE
    # ----------------------------------------------------------
    old_colors = baseline.get("dominant_colors", [])
    new_colors = current.get("dominant_colors", [])
    color_dist = color_scheme_distance(old_colors, new_colors)

    if color_dist >= 0.8:
        pts = int(15 * visual_multiplier)
        add("COLOR_SCHEME_REPLACED", "HIGH", pts,
            f"Brand color palette changed {color_dist:.0%} (was {old_colors[:3]}, now {new_colors[:3]})")
    elif color_dist >= 0.5:
        pts = int(5 * visual_multiplier)
        add("COLOR_SCHEME_CHANGED", "MEDIUM", pts,
            f"Color palette divergence: {color_dist:.0%}")

    # ----------------------------------------------------------
    # 9. NEW EXTERNAL RESOURCE DOMAINS
    # Trusted analytics/CDN domains are filtered out — they appear
    # on legitimate sites dynamically and cause false positives.
    # ----------------------------------------------------------
    old_ext = set(baseline.get("external_domains", []))
    new_ext = set(current.get("external_domains", []))
    added_ext_raw = new_ext - old_ext
    # Filter out known-safe domains
    added_ext = {d for d in added_ext_raw if not is_trusted_domain(d)}
    trusted_skipped = added_ext_raw - added_ext
    if trusted_skipped:
        findings.append({
            "signal": "NEW_TRUSTED_DOMAINS_SKIPPED",
            "severity": "INFO",
            "points": 0,
            "details": f"Skipped (whitelisted): {sorted(trusted_skipped)}",
        })
    if added_ext:
        pts = min(len(added_ext) * 5, 15)
        add("NEW_EXTERNAL_DOMAINS", "MEDIUM", pts, sorted(added_ext))

    # ----------------------------------------------------------
    # 10. NEW SCRIPT SRC DOMAINS
    # Trusted CDN/analytics script domains are filtered out.
    # ----------------------------------------------------------
    old_scripts = set(baseline.get("script_src_domains", []))
    new_scripts = set(current.get("script_src_domains", []))
    added_scripts_raw = new_scripts - old_scripts
    _page_root = _root_domain(urlparse(current["final_url"]).netloc.lower())
    added_scripts = {
        d for d in added_scripts_raw
        if not is_trusted_domain(d)
        and _root_domain(d) != _page_root
    }
    if added_scripts:
        pts = min(len(added_scripts) * 5, 10)
        add("NEW_SCRIPT_SRC_DOMAINS", "MEDIUM", pts,
            sorted(added_scripts))

    # ----------------------------------------------------------
    # 11. FORM ACTION EXFILTRATION
    # Trusted domains (Google Translate, payment processors etc.)
    # are filtered — they appear in legitimate translation widgets.
    # ----------------------------------------------------------
    old_form_actions = set(baseline.get("form_action_domains", []))
    new_form_actions = set(current.get("form_action_domains", []))
    exfil_raw = new_form_actions - old_form_actions
    exfil_domains = {
        d for d in exfil_raw
        if not is_trusted_domain(d)
        and _root_domain(d) != _root_domain(urlparse(current["final_url"]).netloc.lower())
    }
    if exfil_domains:
        add("FORM_ACTION_EXFILTRATION", "CRITICAL", 50,
            f"Form posts to external domain: {sorted(exfil_domains)}")

    # ----------------------------------------------------------
    # 12. NAV LINK DOMAINS CHANGED
    # Own domain variants and social links are filtered out.
    # e.g. site is example.com -> example.com, www.example.com,
    # sub.example.com are all the same org and score 0.
    # ----------------------------------------------------------
    old_nav = set(baseline.get("nav_link_domains", []))
    new_nav = set(current.get("nav_link_domains", []))
    added_nav_raw = new_nav - old_nav

    # Get the site's own root domain for filtering
    page_root = _root_domain(urlparse(current["final_url"]).netloc.lower())

    # Filter: own subdomains, empty strings, trusted social/known domains
    added_nav = {
        d for d in added_nav_raw
        if d
        and _root_domain(d) != page_root
        and not is_trusted_domain(d)
    }
    if added_nav:
        pts = min(len(added_nav) * 3, 10)
        add("NAV_LINKS_NEW_DOMAINS", "MEDIUM", pts,
            f"Nav now links to unknown domains: {sorted(added_nav)}")

    # ----------------------------------------------------------
    # 13. DOM STRUCTURE CHANGED
    # ----------------------------------------------------------
    dom_changed = current.get("dom_hash") != baseline.get("dom_hash")
    if dom_changed:
        findings.append({
            "signal": "DOM_STRUCTURE_CHANGED",
            "severity": "INFO",
            "points": 0,
            "details": "Structural DOM fingerprint changed",
        })

    # ----------------------------------------------------------
    # 14. TITLE CHANGED (full title)
    # ----------------------------------------------------------
    old_title = baseline.get("title", "").strip().lower()
    new_title = current.get("title", "").strip().lower()
    title_changed = old_title and new_title and old_title != new_title

    if title_changed:
        add("TITLE_CHANGED", "HIGH", 20,
            f"'{old_title}' -> '{new_title}'")

    # ----------------------------------------------------------
    # 15. BRAND PREFIX CHANGED
    #     News sites change article titles but keep brand prefix.
    #     If the brand prefix itself changes → strong signal.
    # ----------------------------------------------------------
    old_prefix = baseline.get("title_prefix", "")
    new_prefix = current.get("title_prefix", "")
    if old_prefix and new_prefix and old_prefix != new_prefix:
        add("BRAND_PREFIX_CHANGED", "HIGH", 20,
            f"Brand name changed: '{old_prefix}' -> '{new_prefix}'")

    # ----------------------------------------------------------
    # 16. META DESCRIPTION CHANGED
    # ----------------------------------------------------------
    old_desc = baseline.get("meta_description", "").strip().lower()
    new_desc = current.get("meta_description", "").strip().lower()
    if old_desc and new_desc and old_desc != new_desc:
        findings.append({
            "signal": "META_DESCRIPTION_CHANGED",
            "severity": "INFO",
            "points": 0,
            "details": "Meta description changed",
        })

    # ----------------------------------------------------------
    # 17. CANONICAL URL MISMATCH
    # ----------------------------------------------------------
    canonical = current.get("canonical_url", "") or ""
    if canonical:
        canonical_domain = urlparse(canonical).netloc.lower()
        page_domain = urlparse(current["final_url"]).netloc.lower()
        # Ignore www vs non-www — extremely common legitimate pattern
        canonical_root = _root_domain(canonical_domain)
        page_root_c = _root_domain(page_domain)
        if canonical_domain and canonical_root != page_root_c:
            add("CANONICAL_DOMAIN_MISMATCH", "HIGH", 10,
                f"Canonical points to {canonical_domain} but page is on {page_domain}")

    # ----------------------------------------------------------
    # 18. ROBOTS NOINDEX INJECTED
    # ----------------------------------------------------------
    old_robots = baseline.get("robots_meta", "")
    new_robots = current.get("robots_meta", "")
    if "noindex" not in old_robots and "noindex" in new_robots:
        add("ROBOTS_NOINDEX_INJECTED", "MEDIUM", 10,
            "noindex injected — attacker hiding defaced page from crawlers")

    # ----------------------------------------------------------
    # 19. LANGUAGE / SCRIPT CHANGE
    # ----------------------------------------------------------
    old_script = baseline.get("dominant_script", "unknown")
    new_script = current.get("dominant_script", "unknown")
    if (
        old_script not in ("unknown", "mixed") and
        new_script not in ("unknown", "mixed") and
        old_script != new_script
    ):
        add("LANGUAGE_SCRIPT_CHANGED", "HIGH", 15,
            f"Dominant script: '{old_script}' -> '{new_script}'")

    # ----------------------------------------------------------
    # 20. NEW FORMS
    # ----------------------------------------------------------
    old_forms = baseline.get("identity", {}).get("forms", 0)
    new_forms = current.get("identity", {}).get("forms", 0)
    if new_forms > old_forms:
        pts = min((new_forms - old_forms) * 5, 10)
        add("NEW_FORM", "MEDIUM", pts, f"{old_forms} -> {new_forms}")

    # ==========================================================
    # CORRELATION BONUSES
    # ==========================================================

    signals = {f["signal"] for f in findings}

    if "IDENTITY_LOSS" in signals and (
        "MAJOR_VISUAL_CHANGE" in signals or "MODERATE_VISUAL_CHANGE" in signals
    ):
        add("IDENTITY_VISUAL_CORRELATION", "HIGH", 15,
            "Identity loss and visual change together")

    if "IDENTITY_LOSS" in signals and "NEW_IFRAME" in signals:
        add("IDENTITY_IFRAME_CORRELATION", "HIGH", 15,
            "Identity changed and new iframe appeared")

    if "IDENTITY_LOSS" in signals and "LARGE_OVERLAY" in signals:
        add("IDENTITY_OVERLAY_CORRELATION", "CRITICAL", 20,
            "Identity disappeared while large overlay appeared")

    if "NEW_EXTERNAL_DOMAINS" in signals and "NEW_IFRAME" in signals:
        add("EXTERNAL_IFRAME_CORRELATION", "HIGH", 20,
            "New external domains and iframe together")

    if "TITLE_CHANGED" in signals and "NEW_EXTERNAL_DOMAINS" in signals:
        add("TITLE_DOMAIN_CORRELATION", "HIGH", 20,
            "Title changed alongside new external domains")

    if "TITLE_CHANGED" in signals and (
        "MAJOR_VISUAL_CHANGE" in signals or "MODERATE_VISUAL_CHANGE" in signals
    ):
        add("TITLE_VISUAL_CORRELATION", "HIGH", 15,
            "Title changed alongside major visual difference")

    if "TITLE_CHANGED" in signals and "DOM_STRUCTURE_CHANGED" in signals:
        add("TITLE_DOM_CORRELATION", "MEDIUM", 10,
            "Title and DOM structure both changed")

    if "LANGUAGE_SCRIPT_CHANGED" in signals and "TITLE_CHANGED" in signals:
        add("LANGUAGE_TITLE_CORRELATION", "CRITICAL", 20,
            "Both language script and title changed — full content replacement")

    if "BRAND_PREFIX_CHANGED" in signals and "NEW_EXTERNAL_DOMAINS" in signals:
        add("BRAND_DOMAIN_CORRELATION", "CRITICAL", 20,
            "Brand name replaced and new external domains loaded")

    # Only fire when 2+ untrusted script domains AND DOM changed together
    # Single new script domain is very common (live chat, analytics added by site owner)
    if "NEW_SCRIPT_SRC_DOMAINS" in signals and "DOM_STRUCTURE_CHANGED" in signals:
        if len(added_scripts) >= 2:
            add("SCRIPT_DOM_CORRELATION", "HIGH", 15,
                "Multiple untrusted external scripts injected alongside DOM change")

    if (
        "NEW_EXTERNAL_DOMAINS" in signals and
        "DOM_STRUCTURE_CHANGED" in signals and
        (
            "MAJOR_VISUAL_CHANGE" in signals or
            "MODERATE_VISUAL_CHANGE" in signals
        )
    ):
        add("FULL_REPLACEMENT_CORRELATION", "CRITICAL", 15,
            "External domains + DOM change + visual change — high confidence full replacement")

    if "COLOR_SCHEME_REPLACED" in signals and "TITLE_CHANGED" in signals:
        add("COLOR_TITLE_CORRELATION", "HIGH", 15,
            "Brand colors and title both replaced")

    if "FORM_ACTION_EXFILTRATION" in signals and "LARGE_OVERLAY" in signals:
        add("PHISHING_OVERLAY_CORRELATION", "CRITICAL", 20,
            "Full-page overlay with credential-harvesting form — phishing pattern")

    if "CANONICAL_DOMAIN_MISMATCH" in signals and "TITLE_CHANGED" in signals:
        add("CANONICAL_TITLE_CORRELATION", "CRITICAL", 20,
            "Canonical URL hijacked alongside title change — SEO spam pattern")

    # ==========================================================
    # FINAL SCORE
    # ==========================================================

    confidence = min(score, 100)

    if confidence >= 90:
        verdict = "VERY_LIKELY_DEFACED"
    elif confidence >= 70:
        verdict = "LIKELY_DEFACED"
    elif confidence >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY_NORMAL"

    return {
        "confidence_percent": confidence,
        "raw_score": score,
        "verdict": verdict,
        "likely_defaced": confidence >= DEFACEMENT_THRESHOLD,
        "suspicious": confidence >= SUSPICIOUS_THRESHOLD,
        "findings": findings,
        "metrics": {
            "visual_distance": visual_distance,
            "color_scheme_distance": round(color_dist, 2),
            "identity_elements_lost": identity_lost,
            "new_external_domains": sorted(added_ext),
            "new_script_src_domains": sorted(added_scripts),
            "new_iframe_src_domains": sorted(new_ext_iframe_domains),
            "form_exfil_domains": sorted(exfil_domains),
            "nav_new_domains": sorted(added_nav),
            "old_iframes": old_iframes,
            "new_iframes": new_iframes,
            "old_forms": old_forms,
            "new_forms": new_forms,
            "dom_changed": dom_changed,
            "dominant_script_baseline": old_script,
            "dominant_script_current": new_script,
            "title_prefix_baseline": old_prefix,
            "title_prefix_current": new_prefix,
            "site_type": site_type,
            "visual_multiplier": visual_multiplier,
        },
    }


# ============================================================
# EVIDENCE
# ============================================================

def save_evidence(url, snapshot, analysis, comparison):
    evidence_file = EVIDENCE_DIR / f"{safe_filename(url)}.json"
    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump({
            "url": url,
            "timestamp": snapshot.get("timestamp"),
            "snapshot": snapshot,
            "analysis": analysis,
            "comparison_image": str(comparison) if comparison else None,
        }, f, indent=2, ensure_ascii=False)


# ============================================================
# EMAIL
# ============================================================

def email_configured() -> bool:
    return bool(SMTP_USERNAME and SMTP_PASSWORD and ALERT_EMAIL)


def send_alert_email(url, snapshot, analysis, comparison_path):
    if not email_configured():
        print("[EMAIL] SMTP not configured.")
        return False

    confidence = analysis.get("confidence_percent", 0)
    verdict = analysis.get("verdict", "UNKNOWN")
    findings = analysis.get("findings", [])
    prefix = "[CRITICAL]" if confidence >= 90 else "[HIGH]" if confidence >= 70 else "[WARNING]"

    subject = f"{prefix} Website Defacement Alert - {url} - {confidence}%"

    lines = [
        "WEBSITE DEFACEMENT MONITOR", "",
        f"Website:     {url}",
        f"Final URL:   {snapshot.get('final_url')}",
        f"HTTP Status: {snapshot.get('status_code')}",
        f"Site Type:   {analysis.get('metrics', {}).get('site_type', 'unknown')}",
        "",
        f"Confidence:  {confidence}%",
        f"Verdict:     {verdict}",
        "",
        "Detected signals:",
    ]

    for f in findings:
        lines.append(
            f"  [{f['severity']}] {f['signal']} (+{f['points']}pts): {f['details']}"
        )

    lines += [
        "",
        "Comparison screenshot attached.",
        "LEFT = Initial baseline  |  RIGHT = Latest scan",
        "",
        "This is an automated alert. Investigate before confirming compromise.",
    ]

    msg = EmailMessage()
    msg["From"] = SMTP_USERNAME
    msg["To"] = ALERT_EMAIL
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))

    if comparison_path:
        cp = Path(comparison_path)
        if cp.exists():
            try:
                with open(cp, "rb") as f:
                    img_data = f.read()
                msg.add_attachment(img_data, maintype="image", subtype="png",
                                   filename=cp.name)
                print(f"[EMAIL] Attached: {cp.name} ({len(img_data)/1024:.1f} KB)")
            except Exception as e:
                print(f"[EMAIL ERROR] Attachment failed: {e}")

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            if SMTP_USE_TLS:
                server.starttls(context=ctx)
                server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print("[EMAIL] Sent successfully.")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


# ============================================================
# PROCESS ONE WEBSITE
# ============================================================

async def process_website(browser, semaphore, url: str, site_type: str):

    async with semaphore:

        baseline = load_baseline(url)

        # ====================================================
        # FIRST SCAN — CREATE BASELINE
        # Only save baseline if the scan fully succeeded
        # (status 200, no error). Never baseline a failed page.
        # ====================================================
        if baseline is None:

            snapshot = await scan_website(browser, url)

            success = (
                "error" not in snapshot
                and snapshot.get("status_code") == 200
            )

            if success:
                save_baseline(url, snapshot)
                print(f"[BASELINE] {url}  (type: {site_type})")
            else:
                reason = snapshot.get("error") or f"HTTP {snapshot.get('status_code')}"
                print(f"[BASELINE SKIPPED] {url} — {reason}")

            return {
                "snapshot": snapshot,
                "analysis": {
                    "confidence_percent": 0,
                    "raw_score": 0,
                    "verdict": "BASELINE_CREATED" if success else "BASELINE_FAILED",
                    "likely_defaced": False,
                    "suspicious": False,
                    "findings": [],
                    "metrics": {"site_type": site_type},
                },
                "comparison": None,
                "site_type": site_type,
            }

        # ====================================================
        # SUBSEQUENT SCANS — RETRY ON FAILURE
        # If the site doesn't respond, retry up to MAX_SCAN_RETRIES
        # times. If all retries fail, create comparison image
        # (for evidence) but do NOT send email alert.
        # ====================================================
        snapshot = None
        scan_failed = False

        for attempt in range(1, MAX_SCAN_RETRIES + 1):

            snapshot = await scan_website(browser, url)

            if "error" not in snapshot and snapshot.get("status_code") is not None:
                break  # success

            if attempt < MAX_SCAN_RETRIES:
                print(
                    f"[RETRY] {url} attempt {attempt}/{MAX_SCAN_RETRIES} failed — "
                    f"retrying in {RETRY_DELAY_SECONDS}s"
                )
                await asyncio.sleep(RETRY_DELAY_SECONDS)
            else:
                scan_failed = True
                print(
                    f"[FAILED] {url} — all {MAX_SCAN_RETRIES} attempts failed, "
                    f"skipping email alert"
                )

        # Compare against baseline
        analysis = analyze(snapshot, baseline, site_type)
        comparison = None

        if "error" not in snapshot:
            comparison = create_comparison_image(
                url,
                baseline_screenshot_file(url),
                Path(snapshot["screenshot"]),
                analysis["confidence_percent"],
                analysis["verdict"],
            )
        else:
            # Still create comparison using last known screenshot if available
            last_screenshot = SCREENSHOTS_DIR / f"{safe_filename(url)}.png"
            if last_screenshot.exists():
                comparison = create_comparison_image(
                    url,
                    baseline_screenshot_file(url),
                    last_screenshot,
                    0,
                    "SCAN_FAILED",
                )

        save_evidence(url, snapshot, analysis, comparison)

        print(
            f"[RESULT] {url} | {site_type} | "
            f"{analysis['confidence_percent']}% | {analysis['verdict']}"
            + (" [NO EMAIL — scan failed]" if scan_failed else "")
        )

        # Send email only if scan succeeded AND confidence >= threshold
        if (
            not scan_failed
            and analysis.get("confidence_percent", 0) >= ALERT_THRESHOLD
        ):
            send_alert_email(url, snapshot, analysis, comparison)

        return {
            "snapshot": snapshot,
            "analysis": analysis,
            "comparison": str(comparison) if comparison else None,
            "site_type": site_type,
            "scan_failed": scan_failed,
        }


# ============================================================
# OUTPUT FILES
# ============================================================

def write_outputs(results):
    all_sites, suspicious_sites, defaced_sites = [], [], []

    for result in results:
        snapshot = result["snapshot"]
        analysis = result["analysis"]
        url = snapshot.get("url")

        record = {
            "url": url,
            "site_type": result.get("site_type", "static"),
            "final_url": snapshot.get("final_url"),
            "timestamp": snapshot.get("timestamp"),
            "status_code": snapshot.get("status_code"),
            "confidence_percent": analysis.get("confidence_percent", 0),
            "verdict": analysis.get("verdict"),
            "findings": analysis.get("findings", []),
            "metrics": analysis.get("metrics", {}),
            "baseline_screenshot": str(baseline_screenshot_file(url)),
            "latest_screenshot": snapshot.get("screenshot"),
            "comparison": result.get("comparison"),
        }

        all_sites.append(record)
        if analysis.get("suspicious"):
            suspicious_sites.append(record)
        if analysis.get("likely_defaced"):
            defaced_sites.append(record)

    now = datetime.now(timezone.utc).isoformat()
    sort_key = lambda x: x["confidence_percent"]

    with open(ALL_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now, "total_sites": len(all_sites),
                   "sites": all_sites}, f, indent=2, ensure_ascii=False)

    with open(SUSPICIOUS_FILE, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now, "threshold_percent": SUSPICIOUS_THRESHOLD,
                   "total_suspicious": len(suspicious_sites),
                   "sites": sorted(suspicious_sites, key=sort_key, reverse=True)},
                  f, indent=2, ensure_ascii=False)

    with open(LIKELY_DEFACED_FILE, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now, "threshold_percent": DEFACEMENT_THRESHOLD,
                   "total_likely_defaced": len(defaced_sites),
                   "sites": sorted(defaced_sites, key=sort_key, reverse=True)},
                  f, indent=2, ensure_ascii=False)

    return all_sites, suspicious_sites, defaced_sites


# ============================================================
# ONE FULL SCAN CYCLE
# ============================================================

async def run_cycle(cycle_number: int):

    domain_entries = load_domains()

    if not domain_entries:
        print("[WARNING] No domains to scan this cycle.")
        return

    print()
    print("==========================================")
    print(f"  CYCLE #{cycle_number}  |  {datetime.now(timezone.utc).isoformat()}")
    print("==========================================")
    print(f"Domains loaded: {len(domain_entries)}")
    for url, stype in domain_entries:
        print(f"  [{stype}] {url}")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True, args=["--disable-dev-shm-usage"]
        )
        tasks = [
            process_website(browser, semaphore, url, stype)
            for url, stype in domain_entries
        ]
        results = await asyncio.gather(*tasks)
        await browser.close()

    all_sites, suspicious_sites, defaced_sites = write_outputs(results)

    print()
    print("==========================================")
    print("                 SUMMARY")
    print("==========================================")
    print(f"Total:          {len(all_sites)}")
    print(f"Suspicious:     {len(suspicious_sites)}")
    print(f"Likely defaced: {len(defaced_sites)}")

    if defaced_sites:
        print()
        print("!!! LIKELY DEFACED !!!")
        for site in defaced_sites:
            print(f"\n  {site['confidence_percent']}%  {site['verdict']}  [{site['site_type']}]")
            print(f"  {site['url']}")
            for finding in site["findings"]:
                print(f"  - [{finding['severity']}] {finding['signal']}: {finding['details']}")

    print()
    print(f"  All results:    {ALL_RESULTS_FILE}")
    print(f"  Suspicious:     {SUSPICIOUS_FILE}")
    print(f"  Likely defaced: {LIKELY_DEFACED_FILE}")
    print(f"  Evidence:       {EVIDENCE_DIR}/")
    print(f"  Comparisons:    {COMPARISONS_DIR}/")


# ============================================================
# MAIN — SCHEDULER LOOP
# ============================================================

async def main():

    create_directories()

    if not DOMAINS_FILE.exists():
        print(f"[ERROR] {DOMAINS_FILE} does not exist.")
        print("Create domains.txt with one URL per line.")
        print("Optional site type tag: https://example.com  #type:news")
        sys.exit(1)

    print()
    print("==========================================")
    print("       WEBSITE DEFACEMENT MONITOR")
    print("==========================================")
    print(f"Scan interval:            {SCAN_INTERVAL_SECONDS}s")
    print(f"Max concurrent:           {MAX_CONCURRENT_SCANS}")
    print(f"Suspicious threshold:     {SUSPICIOUS_THRESHOLD}%")
    print(f"Defaced threshold:        {DEFACEMENT_THRESHOLD}%")
    print(f"Email alert threshold:    {ALERT_THRESHOLD}%")
    print()

    if email_configured():
        print(f"Email: ENABLED -> {ALERT_EMAIL} via {SMTP_HOST}:{SMTP_PORT}")
    else:
        print("[WARNING] Email alerts not configured.")

    print()
    print("Site types (affect visual scoring weight):")
    print("  static     -> full visual weight  (x1.0)")
    print("  ecommerce  -> reduced weight       (x0.5)")
    print("  news       -> minimal weight       (x0.3)")
    print()
    print("Tag in domains.txt: https://bbc.com  #type:news")
    print("Domains re-read every cycle — no restart needed.")
    print()

    cycle = 0
    while True:
        cycle += 1
        try:
            await run_cycle(cycle)
        except Exception as e:
            print(f"[ERROR] Cycle #{cycle} failed: {e}")

        print(f"\nNext scan in {SCAN_INTERVAL_SECONDS}s\n")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Monitor stopped.")
        sys.exit(0)
