<p align="center">
  <img src="app/static/img/logo.png" width="150" alt="SENTINALL Logo">
</p>

# 🛡️ SENTINALL // Link Guard Logic

SENTINALL is a professional-grade link protection and redirection framework. It is engineered to secure digital distribution channels against unauthorized bypass scripts, automated scrapers, and ad-blockers.

---

## 🚀 Deployment Matrix

The platform is container-ready and can be deployed on any modern cloud infrastructure.

| Provider | Config | Deployment Note |
| :--- | :--- | :--- |
| **Koyeb** | `Dockerfile` | **Select Docker** in deployment settings |
| **Render** | `Dockerfile` | **Select Docker** as the runtime |
| **Heroku** | `heroku.yml` | `git push heroku main` |
| **Vercel** | `vercel.json` | `vercel --prod` |

> [!IMPORTANT]
> **Cloud Settings**: When deploying to platforms like Koyeb, Render, Heroku, or Vercel, you **MUST** fill in the environment variables (found in `.env.example`) in the **Environment Variables** or **Settings** section of the platform's dashboard.

---

## 🔑 Security Configuration

To initialize your node, you must generate unique security ciphers. You can run these commands for free on [Google Colab](https://colab.research.google.com/) or [Replit](https://replit.com/):

### 1. App Secret (Session Signing)
```python
import secrets
print(secrets.token_hex(32))
```

### 2. Encryption Key (Fernet)
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

> [!IMPORTANT]
> **Keep your keys secret.** If you lose your `ENCRYPTION_KEY`, all active links will become invalid and un-decryptable.

---

## 🛠️ Installation & Deployment

### 1. Linux / VPS Deployment (Standard)
Follow these steps to deploy SENTINALL on a standard Linux server:

```bash
# 1. Clone the repository
git clone https://github.com/aquib4040/sentinall.git
cd sentinall

# 2. Create and activate a Virtual Environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install required dependencies
pip install -r requirements.txt

# 4. Configure Environment Variables
# IMPORTANT: You must create a .env file and fill in all required credentials
cp .env.example .env
nano .env  # Edit with your specific keys and MongoDB URI

# 5. Launch with Production Server
gunicorn --bind 0.0.0.0:8000 run:app
```

### 2. Local Development
For testing on your local machine:
1.  **Repeat steps 1-4** above.
2.  **Launch Dev Server**:
    ```bash
    python run.py
    ```

---

## 🛡️ The Guard Logic

The platform implements a multi-layer verification stack:

*   **Environmental Fingerprinting**: Analyzes browser metadata to ensure link integrity across the redirection flow.
*   **State Persistence**: Uses cross-page cookie validation to block direct access to destination endpoints.
*   **Referer Enforcement**: Strict validation of the source domain to neutralize "skip-script" injections.
*   **Temporal Checks**: Real-time monitoring of user interaction speed to detect bot-like behavior.

> [!CAUTION]
> **Technical Disclaimer**: SENTINALL is built to deter standard users and common bypass scripts. However, **professional users** with advanced scraping tools or specialized bypass scripts may still find ways to circumvent these protections. Security is a deterrent, not an absolute.

---

## 📊 Technical Architecture

The platform follows a **Modular Factory Pattern**, separating concerns for maximum maintainability:

- **Blueprints**: Decoupled routes for Auth, Dashboard, Admin, and Redirection logic.
- **Models**: Clean MongoDB abstraction for users, links, and analytics.
- **Utils**: Centralized security and decorator logic.

---

## 🔌 API Integration (Professional)

Integrate SENTINALL into your existing bots or automation pipelines using our REST API.

### PHP Implementation Example
```php
<?php
$target = "https://your-source-content.com/data";
$api_key = "YOUR_SENTINALL_KEY";
$domain = "https://your-app.com";

$endpoint = "$domain/api/create?api=$api_key&url=" . urlencode($target);
$response = json_decode(file_get_contents($endpoint), true);

if ($response['status'] === 'success') {
    echo "Guard Active: " . $response['shortenedUrl'];
} else {
    echo "Error: " . $response['message'];
}
?>
```

---

## 🤖 AI-Built Infrastructure

**"Even I myself made this fix using AI! 🚀"**

I built and refined this entire project using advanced AI logic. Every bug fix, UI enhancement, and architectural decision was guided by machine intelligence to ensure a state-of-the-art implementation.

**Maintenance Policy**:
If you find a bug:
1.  **Use AI** to analyze and fix the logic.
2.  **Submit a Pull Request** with the signature: *"Even I myself made this fix using AI! 🚀"*

---

## 🔐 Google reCAPTCHA Configuration

SENTINALL uses human verification to prevent automated bypasses. To ensure this works correctly, you must use the specific version below:

**Required Version**: `reCAPTCHA v2` (The "I'm not a robot" Checkbox)
1.  Go to the [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin).
2.  Create a new site and select **reCAPTCHA v2** -> **"I'm not a robot" Checkbox**.
3.  Add your domain (e.g., `sentinall.vercel.app`) to the allowed list.
4.  Copy the **Site Key** and **Secret Key** into your Operator Settings in the SENTINALL Dashboard.

> [!IMPORTANT]
> Do NOT use reCAPTCHA v3 or the "Invisible" version, as the current SENTINALL UI is optimized for the v2 challenge-response flow.

---

## 🛠️ Post-Mortem: The 500 Error Fix
In version 1.0.1, a `CRITICAL_RUNTIME_ERROR` was identified and patched:
*   **The Cause**: A logic failure occurred when the system attempted to fetch security settings for a link whose owner record had been de-synchronized.
*   **The Fix**: Implemented a "Safety Guard" that validates user existence before every verification step.
*   **Mobile UI**: Refactored the error page typography to use responsive scaling, preventing text overflow on high-density mobile displays.

---

## 📢 Community & Support

Stay updated with the latest guard logic updates and community nodes:
*   **Telegram**: [t.me/sentinall_bots](https://t.me/canon_bots)

---

## 📜 License
Open-source distribution for professional and educational use.