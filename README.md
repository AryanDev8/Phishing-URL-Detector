# 🛡️ Phishing URL Detector

A client-side web application that analyzes URLs for phishing indicators using 10 heuristic checks — no backend, no API calls, everything runs in the browser.

Built with **React + Vite** as part of my cybersecurity portfolio, focused on understanding how attackers craft deceptive URLs — a foundational concept in GRC and security risk assessment.

---

## 🧠 How It Works

The app accepts any URL as input and runs it through 10 independent heuristic checks. Each check carries a weighted risk score. The scores are summed and clamped to 100, then mapped to one of three verdicts:

| Score Range | Verdict |
|---|---|
| 0 – 29 | ✅ LIKELY SAFE |
| 30 – 59 | ⚠️ SUSPICIOUS |
| 60 – 100 | 🔴 HIGH RISK |

URL parsing is handled entirely by the browser's native `URL` constructor — no external libraries or network requests.

---

## 🔍 The 10 Heuristic Checks

| # | Check | Risk Weight | Description |
|---|---|---|---|
| 1 | **No HTTPS** | +25 | HTTP protocol — traffic can be intercepted |
| 2 | **IP as hostname** | +30 | Raw IP address instead of domain — rare in legitimate sites |
| 3 | **Suspicious TLD** | +20 | Free/high-abuse TLDs: `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.top`, etc. |
| 4 | **Lookalike domain** | +35 | Levenshtein distance ≤ 2 from a trusted brand (PayPal, Amazon, Apple, etc.) |
| 5 | **Excessive subdomains** | +20 | More than 4 domain levels — e.g. `login.verify.paypal.attacker.com` |
| 6 | **Phishing keywords** | +10/+25 | Words like `login`, `verify`, `secure`, `password`, `confirm` in the URL |
| 7 | **Long URL** | +15 | URLs over 100 characters — used to obscure malicious segments |
| 8 | **Excessive hyphens** | +15 | 3+ hyphens in domain — e.g. `paypal-secure-login-verify.com` |
| 9 | **@ symbol** | +30 | Everything before `@` is ignored by browser — classic deception trick |
| 10 | **URL shortener** | +15 | bit.ly, tinyurl, t.co etc. — hides the real destination |

---

## 🧬 Levenshtein Distance — The Lookalike Algorithm

The lookalike domain detection uses the **Levenshtein distance algorithm** — it measures the minimum number of single-character edits (insert, delete, replace) needed to transform one string into another.

```
paypal  →  paypa1   (1 substitution)   distance = 1 → FLAGGED
amazon  →  arnazon  (1 substitution)   distance = 1 → FLAGGED
google  →  g00gle   (2 substitutions)  distance = 2 → FLAGGED
github  →  gitlab   (3 substitutions)  distance = 3 → NOT flagged
```

Any domain within **2 edits** of a trusted brand triggers a +35 risk score — the highest weighted check in the tool.

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 18 |
| Build Tool | Vite |
| Styling | Inline CSS (no external UI library) |
| Logic | Vanilla JavaScript |
| URL Parsing | Native browser `URL` API |
| Animations | CSS `@keyframes` |

Zero external dependencies beyond React itself.

---

## 🚀 Getting Started

### Prerequisites
- Node.js v18+
- npm

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/phishing-detector.git

# Navigate into the project
cd phishing-detector

# Install dependencies
npm install

# Start the development server
npm run dev
```

Open `http://localhost:5173` in your browser.

### Build for Production

```bash
npm run build
```

---

## 🧪 Try These Example URLs

| URL | Expected Result |
|---|---|
| `https://github.com/login` | ✅ LIKELY SAFE |
| `http://paypa1-secure-login.xyz/verify/account` | 🔴 HIGH RISK |
| `https://login.verify.amazon.support-check.com` | 🔴 HIGH RISK |
| `https://bit.ly/3xK9mPf` | ⚠️ SUSPICIOUS |

---

## 📁 Project Structure

```
phishing-detector/
├── public/
├── src/
│   ├── App.jsx          # Main component — all logic and UI
│   └── main.jsx         # React entry point
├── index.html
├── package.json
└── vite.config.js
```

---

## ⚠️ Limitations

This tool uses **heuristic analysis only** — it does not query threat intelligence feeds or external databases. This means:

- **False positives** — legitimate URLs may occasionally score as suspicious
- **False negatives** — sophisticated phishing URLs using clean domains will not be detected
- **No real-time data** — newly registered phishing domains are not checked against any blacklist

Production-grade phishing detection would combine heuristics with:
- VirusTotal API (real-time blacklist)
- WHOIS domain age lookup (new domains = high risk)
- SSL certificate transparency logs
- ML classifier trained on PhishTank dataset

---

## 🔮 Planned Improvements

- [ ] VirusTotal API integration
- [ ] Domain age lookup via WHOIS
- [ ] Scan history log (localStorage)
- [ ] Browser extension version
- [ ] Export scan report as PDF
- [ ] ML-based scoring layer

---

## 👤 Author

**Aryan**
Final-year B.Sc. IT — D.G. Ruparel College, Mumbai
| InProgrss: CEH V.13 | Targeting Cybersecurity Consulting & GRC roles

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](linkedin.com/in/aryan-kamble-)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/AryanDev8)

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

> _"Understanding how attackers craft deceptive URLs is foundational to cybersecurity risk assessment."_
