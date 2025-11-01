# 🛰️ Cyber Threat Intelligence Bot

An automated **Cyber Threat Intelligence Feed Parser** and **Telegram Bot** built using Python.  
It delivers real-time updates from trusted cybersecurity sources — including **CVE data, exploit feeds, threat intelligence, blogs, and security tools** — directly to your Telegram chat.

---

## 🚀 Features

- 🔍 **CVE Updates** – Fetches the latest vulnerabilities from CVE Details API.  
- 🧱 **RSS Feeds Integration** – Aggregates content from Exploit-DB, The Hacker News, DarkReading, GBHackers, and more.  
- 🛰️ **Categorized Intelligence Feeds**
  - Vulnerabilities & Exploits  
  - Cybersecurity News  
  - Security Blogs  
  - Red & Blue Team Posts  
  - Tools & Threat Intelligence  
  - Tech & How-To Articles  
- 💬 **Telegram Integration** – Get all updates instantly through simple chat commands.  
- ⚙️ **Customizable** – Add or remove RSS feeds easily.  
- 📄 **Markdown Support** – Clean and readable Telegram message formatting.  

---

## 🧠 Commands Overview

| Command | Description |
|----------|-------------|
| `/start` | Show available commands |
| `/vuln` | Get latest vulnerabilities and CVEs |
| `/news` | Fetch recent cybersecurity news |
| `/blogs` | Get top security blogs |
| `/tech` | Tech & gadget updates |
| `/red_blue_team` | Red and Blue Team content |
| `/tools` | Latest security tools |
| `/threat_intel_feed` | Threat intelligence reports |

---

## 🛠️ Tech Stack

- **Language:** Python 3  
- **APIs:** CVE Details API, RSS feeds  
- **Libraries:**  
  - `feedparser`  
  - `requests`  
  - `python-telegram-bot`  
  - `datetime`  
  - `logging`

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/cyber-threat-intel-bot.git
cd cyber-threat-intel-bot
```
## 2. Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate   # For Linux/Mac
venv\Scripts\activate      # For Windows
```
## 3. Install dependencies
```bash
pip install -r requirements.txt
```

## 4. Set up environment variables
Create a .env file in the project root and add:
```bash
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
CVE_API_BEARER_TOKEN=your_cve_api_token
```
⚠️ Make sure not to commit this file to GitHub!

## 5. Run the bot
```bash
python main.py
```

## 🧩 Folder Structure
```bash
cyber-threat-intel-bot/
│
├── main.py                # Core bot code
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
└── .env                   # API tokens (excluded from git)

```

## Use Case

Ideal for:
- Cybersecurity analysts
- Threat hunters & SOC teams
- Students & researchers in cybersecurity
- Security content aggregators

## Disclaimer

This project is for educational and research purposes only.
Use it responsibly and ensure compliance with your organization’s security policies.
