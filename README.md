<p align="center">
  <img src="app/static/img/logo.png" width="120" alt="SENTINALL">
</p>

<h1 align="center">SENTINALL</h1>
<p align="center">
  <strong>Military-Grade Link Protection &amp; Anti-Bypass Framework</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/flask-3.x-black?logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/mongodb-atlas-green?logo=mongodb&logoColor=white" alt="MongoDB">
  <img src="https://img.shields.io/badge/license-MIT-purple" alt="License">
</p>

---

SENTINALL is a self-hosted link protection platform engineered to secure URL shortener monetization pipelines. It wraps destination URLs behind multi-layer verification — browser fingerprinting, cookie validation, reCAPTCHA challenges, temporal checks, and IP enforcement — making automated bypass scripts effectively useless.

**Built for operators who are tired of losing revenue to bypass tools.**

---

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Deployment](#-deployment)
- [Environment Variables](#-environment-variables)
- [API Reference](#-api-reference)
- [Security Stack](#-security-stack)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Category | Details |
|---|---|
| **Anti-Bypass Engine** | 16+ signal browser fingerprinting, cookie state tracking, referer enforcement, temporal speed checks |
| **One-Time Redirects** | Destination URLs are never exposed in network tab or JSON responses — uses opaque, auto-expiring tokens |
| **reCAPTCHA Integration** | Configurable reCAPTCHA v2 on both start and verify steps |
| **IP Enforcement** | Optional same-IP requirement between start → verify (blocks VPN switchers) |
| **Auto-Expire Links** | Configurable TTL, visit limits, and auto-disable after first use |
| **Operator Dashboard** | Real-time analytics, link generation, and per-operator security settings |
| **Admin Panel** | Owner-level user management, platform-wide stats, and user moderation |
| **Security Headers** | X-Frame-Options, CSP, CSRF protection, no-cache on authenticated pages |
| **Bot Detection** | Blocks headless Chrome, Selenium, Puppeteer, curl, Postman, and 10+ automation tools |
| **Multi-Operator** | Each user gets their own API key, reCAPTCHA keys, shortener config, and security settings |

---

## 🏗 Architecture

```
sentinall/
├── app/
│   ├── __init__.py          # App factory, security headers, CSRF middleware
│   ├── config.py            # Environment-based configuration
│   ├── models/
│   │   ├── database.py      # MongoDB connection + indexes
│   │   ├── link.py          # Link CRUD operations
│   │   ├── user.py          # User management
│   │   └── stats.py         # Analytics aggregation
│   ├── routes/
│   │   ├── auth.py          # Login, register, owner auth
│   │   ├── dashboard.py     # User dashboard + settings
│   │   ├── admin.py         # Owner admin panel
│   │   ├── api.py           # REST API + analytics endpoints
│   │   ├── links.py         # Start → verify → redirect flow
│   │   └── main.py          # Landing page
│   ├── utils/
│   │   ├── security.py      # Fingerprinting, bot detection, encryption
│   │   └── decorators.py    # Auth guards (@login_required, @owner_required)
│   ├── templates/           # Jinja2 templates (glassmorphic dark UI)
│   └── static/              # CSS, JS, images
├── run.py                   # Application entry point
├── Dockerfile               # Container build
├── requirements.txt         # Python dependencies
└── .env.example             # Required environment variables
```

**Design Pattern:** Flask Application Factory with Blueprint-based routing and MongoDB persistence.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- MongoDB Atlas cluster (or local MongoDB)
- reCAPTCHA v2 site + secret keys ([get them here](https://www.google.com/recaptcha/admin))
- A URL shortener API (e.g., ModLinks, GPLinks)

### Local Development

```bash
# Clone
git clone https://github.com/aquib4040/sentinall.git
cd sentinall

# Virtual environment
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your credentials (see Environment Variables section)

# Run
python run.py
```

The app will be available at `http://localhost:8000`.

### Production

```bash
gunicorn --bind 0.0.0.0:8000 --workers 4 run:app
```

---

## ☁ Deployment

SENTINALL is container-ready and supports all major cloud platforms:

| Platform | Config File | Command |
|---|---|---|
| **Docker** | `Dockerfile` | `docker build -t sentinall . && docker run -p 8000:8000 sentinall` |
| **Koyeb** | `Dockerfile` | Select Docker runtime in dashboard |
| **Render** | `Dockerfile` | Select Docker runtime in dashboard |
| **Heroku** | `heroku.yml` | `git push heroku main` |
| **Vercel** | `vercel.json` | `vercel --prod` |

> [!IMPORTANT]
> You **must** configure all environment variables in the platform's dashboard before deploying. See the section below.

---

## 🔐 Environment Variables

Create a `.env` file or configure these in your cloud platform's settings:

| Variable | Description | How to Generate |
|---|---|---|
| `SECRET_KEY` | Flask session signing key | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ENCRYPTION_KEY` | Fernet key for token encryption | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `MONGODB_URI` | MongoDB connection string | From MongoDB Atlas dashboard |
| `MONGODB_DB_NAME` | Database name | Any name (e.g., `sentinall`) |
| `OWNER_EMAIL` | Admin panel login email | Your email |
| `OWNER_PASSWORD` | Admin panel login password + registration gate | A strong password |

> [!CAUTION]
> **Keep your `ENCRYPTION_KEY` safe.** If you lose it, all existing protected links become permanently invalid and cannot be recovered.

---

## 📡 API Reference

### Create Protected Link

```
POST /api/create
Content-Type: application/json

{
  "api": "YOUR_API_KEY",
  "url": "https://destination-url.com"
}
```

**Response:**
```json
{
  "status": "success",
  "shortenedUrl": "https://your-app.com/start/gAAAAA..."
}
```

> [!NOTE]
> The API also supports GET requests for backward compatibility: `/api/create?api=KEY&url=URL`  
> However, **POST is strongly recommended** as GET exposes your API key in server logs and browser history.

### PHP Integration

```php
<?php
$api_key = "YOUR_API_KEY";
$domain  = "https://your-sentinall.com";
$target  = "https://destination-content.com/data";

$ch = curl_init("$domain/api/create");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS => json_encode(['api' => $api_key, 'url' => $target]),
    CURLOPT_RETURNTRANSFER => true
]);

$response = json_decode(curl_exec($ch), true);
curl_close($ch);

echo $response['status'] === 'success'
    ? "Protected Link: " . $response['shortenedUrl']
    : "Error: " . $response['message'];
?>
```

### Python Integration

```python
import requests

response = requests.post("https://your-sentinall.com/api/create", json={
    "api": "YOUR_API_KEY",
    "url": "https://destination-url.com"
})

data = response.json()
if data["status"] == "success":
    print(f"Protected: {data['shortenedUrl']}")
```

---

## 🛡 Security Stack

SENTINALL implements defense-in-depth with the following layers:

### Verification Flow

```
User clicks link
      │
      ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌───────────┐
│  /start/    │───▶│  Shortener   │───▶│  /verify/   │───▶│  /r/token  │
│  Fingerprint│    │  Redirect    │    │  reCAPTCHA  │    │  One-Time  │
│  + Cookies  │    │  (ads here)  │    │  + Checks   │    │  Redirect  │
└─────────────┘    └──────────────┘    └─────────────┘    └───────────┘
      │                                       │                  │
      └──── Fingerprint A ────────────────── Fingerprint B ──── Compare
```

### Anti-Bypass Measures

| Layer | What It Does |
|---|---|
| **Browser Fingerprinting** | 16+ signals (User-Agent, Client Hints, Sec-Fetch-*, Accept headers) — compared between start and verify |
| **Cookie State Tracking** | Validates cookie count and session presence remain consistent across steps |
| **Temporal Validation** | Configurable minimum time between start → verify (catches speed-running bots) |
| **IP Enforcement** | Optional same-IP requirement (blocks VPN/proxy switching mid-flow) |
| **Referer Validation** | Checks that the verify page was reached via the configured shortener domain |
| **One-Time Redirect Tokens** | Destination URLs never appear in network tab — opaque tokens expire in 30 seconds |
| **Bot/Automation Blocking** | Blocks Selenium, Puppeteer, PhantomJS, curl, wget, Postman, headless Chrome |
| **reCAPTCHA v2** | Configurable on both start and verify steps |

### Infrastructure Security

| Protection | Implementation |
|---|---|
| **CSRF** | Session-bound tokens on all POST forms |
| **Security Headers** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` |
| **Session Security** | `HttpOnly`, `Secure`, `SameSite=Lax` cookies |
| **Error Sanitization** | Stack traces logged server-side, generic messages shown to users |
| **Cloudflare-Aware IP** | Proper `CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For` chain |
| **Permissions Policy** | Geolocation, microphone, camera, and payment APIs disabled |
| **No-Cache on Auth Pages** | Prevents back-button access to authenticated content |

---

## ❓ FAQ

<details>
<summary><strong>What reCAPTCHA version should I use?</strong></summary>

**reCAPTCHA v2 — "I'm not a robot" Checkbox only.** Do NOT use v3 or Invisible mode. The UI is built for the v2 challenge-response widget.

1. Go to [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
2. Select **reCAPTCHA v2** → **"I'm not a robot" Checkbox**
3. Add your domain to the allowed list
4. Copy Site Key and Secret Key into your SENTINALL dashboard settings
</details>

<details>
<summary><strong>Can someone bypass SENTINALL by looking at the network tab?</strong></summary>

**No.** SENTINALL uses one-time opaque redirect tokens. The actual destination URL never appears in any JSON response or network request. The token expires in 30 seconds and self-destructs after a single use. All an attacker would see is:
```json
{"status": "success", "r": "Xk9f2mQz..."}
```
</details>

<details>
<summary><strong>What happens if fingerprints don't match?</strong></summary>

The link is permanently marked as **bypassed** and the user sees a roast message. The specific bypass reason (device swap, cookie mismatch, speed-run, etc.) is logged in the database for the operator to review — but never shown to the attacker.
</details>

<details>
<summary><strong>Can I use this with any URL shortener?</strong></summary>

Yes. SENTINALL works with any shortener that has a `GET` API returning `{"status": "success", "shortenedUrl": "..."}`. Popular ones include ModLinks, GPLinks, Shrinkme, and similar services.
</details>

<details>
<summary><strong>How do I add a new operator?</strong></summary>

1. Set `OWNER_PASSWORD` in your environment variables
2. Share the password with the new operator
3. They go to `/register` and enter the admin password + their credentials
4. Each operator gets isolated API keys, reCAPTCHA keys, and security settings
</details>

<details>
<summary><strong>What browsers are supported?</strong></summary>

**Chrome and Edge only** (Chromium-based). SENTINALL intentionally blocks Firefox, Safari, and other browsers to leverage Chromium-specific Client Hints headers for stronger fingerprinting. Non-Chromium browsers, bots, and automation tools are redirected to a restriction page.
</details>

<details>
<summary><strong>Can I self-host this on a VPS?</strong></summary>

Yes. Clone the repo, install dependencies, set up a `.env` file, and run with `gunicorn`. Recommended: use Nginx as a reverse proxy with SSL termination, behind Cloudflare for DDoS protection.
</details>

<details>
<summary><strong>What database do I need?</strong></summary>

MongoDB. The recommended setup is a free-tier [MongoDB Atlas](https://www.mongodb.com/atlas) cluster. The application auto-creates all required collections and indexes on first startup.
</details>

<details>
<summary><strong>I lost my ENCRYPTION_KEY. Can I recover my links?</strong></summary>

**No.** The encryption key is used to generate link tokens. Without it, existing tokens cannot be validated or decrypted. You will need to generate a new key and recreate all links.
</details>

<details>
<summary><strong>Why do I see "Property assignment expected" errors in my IDE?</strong></summary>

These are **false positives** from your IDE's JavaScript parser. It doesn't understand Jinja2 template syntax (`{{ }}`) inside HTML attributes. The templates are valid and work correctly at runtime.
</details>

---

## 🤖 AI-Built & Maintained

This project was built and refined using advanced AI. Every security layer, UI component, and architectural decision was engineered with machine intelligence.

**Maintenance Policy:**
- Found a bug? Use AI to analyze and fix the logic
- Submit a PR with the signature: *"Even I myself made this fix using AI! 🚀"*

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## 📢 Community

- **Telegram**: [t.me/canon_bots](https://t.me/canon_bots)

---

## 📜 License

MIT License — free for personal, educational, and commercial use.

```
MIT License

Copyright (c) 2024 SENTINALL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```