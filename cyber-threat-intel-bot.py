import logging
import requests
import feedparser
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# --- Configuration ---
# Replace with your actual tokens
TELEGRAM_BOT_TOKEN = 'Enter your token here'
CVE_API_BEARER_TOKEN = 'Enter your api key here'

# RSS Feeds categorized for easier management
RSS_FEEDS = {
    # Vulnerability & Exploits
    'exploitdb': 'https://www.exploit-db.com/rss.xml',
    'bleepingcomputer': 'https://www.bleepingcomputer.com/feed/',

    # General Cybersecurity News
    'thehackersnews': 'https://feeds.feedburner.com/TheHackersNews',
    'securityweek': 'https://feeds.feedburner.com/securityweek',
    'cybersecuritynews': 'https://feeds.feedburner.com/cyber-security-news',
    'darkreading': 'https://www.darkreading.com/rss.xml',

    # Security Blogs
    'invicti': 'https://www.invicti.com/blog/feed/',
    'huggingface': 'https://huggingface.co/blog/feed.xml',
    'xda_security': 'https://www.xda-developers.com/feed/tag/security/',

    # Tech News & Updates
    'kali': 'https://www.kali.org/rss.xml',
    'gbhackers': 'https://feeds.feedburner.com/gbhackers/cybersecurity',
    'hindustan_howto': 'https://tech.hindustantimes.com/rss/how-to',
    'hindustan_mobile_reviews': 'https://tech.hindustantimes.com/rss/mobile/reviews',
    'hindustan_mobile_news': 'https://tech.hindustantimes.com/rss/mobile/news',
    'hindustan_laptops_news': 'https://tech.hindustantimes.com/rss/laptops-pc/news',
    'gadgets360_latest': 'https://feeds.feedburner.com/gadgets360-latest',
    'techspot': 'https://www.techspot.com/backend.xml',
    'techradar': 'https://www.techradar.com/feeds.xml',
    'pureinfotech': 'https://pureinfotech.com/feed/',
    'androidauthority_feed': 'http://feed.androidauthority.com/',

    # Red/Blue Team
    'hackthebox_red': 'https://www.hackthebox.com/rss/blog/red-teaming',
    'hackthebox_blue': 'https://www.hackthebox.com/rss/blog/blue-teaming',

    # Tools
    'kitploit': 'http://feeds.feedburner.com/Kitploit',
    'secpod': 'https://www.secpod.com/blog/feed/',

    # Threat Intelligence
    'dfir_report': 'https://thedfirreport.com/feed/',
    'checkpoint': 'https://research.checkpoint.com/category/threat-research/feed/',
    'socprime': 'https://socprime.com/feed/',
    'juniper': 'https://blogs.juniper.net/threat-research/feed',
    'portswigger': 'https://portswigger.net/research/rss',
    'unit42': 'https://unit42.paloaltonetworks.com/feed/',
}

# Websites to check out manually
TECH_CHECKOUT_LINKS = {
    'Gadgets360': 'https://www.gadgets360.com/',
    'TechDhee': 'https://techdhee.in/',
    'Android Authority': 'https://www.androidauthority.com/',
}

# CVE API Configuration
CVE_API = {
    'url': 'https://www.cvedetails.com/api/v1/vulnerability/search',
    'headers': {
        'Authorization': f'Bearer {CVE_API_BEARER_TOKEN}',
        'Accept': 'application/json',
    }
}

# --- Helper Functions ---
def escape_markdown(text):
    if not text:
        return ''
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + c if c in escape_chars else c for c in text)

def format_rss_item(item):
    title = escape_markdown(item.get('title', 'No Title'))
    link = item.get('link', '')
    published = item.get('published', 'N/A')
    return f"*{title}*\n{link}\n_Published: {published}_"

def fetch_rss(feed_url, max_items=3):
    try:
        feed = feedparser.parse(feed_url)
        if feed.bozo:
            logging.warning(f"Failed to parse feed: {feed_url}. Reason: {feed.bozo_exception}")
            return []
        items = feed.entries[:max_items]
        return [format_rss_item(item) for item in items]
    except Exception as e:
        logging.error(f"Error fetching RSS feed {feed_url}: {e}")
        return []


def fetch_cve(max_items=5):
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)
    params = {
        'publishDateStart': yesterday.strftime('%Y-%m-%d'),
        'publishDateEnd': today.strftime('%Y-%m-%d'),
    }
    try:
        response = requests.get(CVE_API['url'], headers=CVE_API['headers'], params=params, timeout=15)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        results = data.get('results', [])[:max_items]
        formatted = []
        for vuln in results:
            cve_id = escape_markdown(vuln.get('cveId', 'N/A'))
            summary = escape_markdown(vuln.get('summary', 'No summary'))
            published = vuln.get('publishDate', 'N/A')
            exploit_status = "Exploit Available" if vuln.get('exploitExists') else "No Known Exploit"
            formatted.append(f"*{cve_id}*\n{summary}\n_Since: {published} | {exploit_status}_")
        return formatted
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching CVE data: {e}")
        return [f"Error fetching CVE data: {e}"]
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching CVEs: {e}")
        return []

# --- Command Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = (
        "Welcome to your Cyber & Tech Intel Assistant!\n\n"
        "Here are the available commands:\n"
        "/vuln  - Latest Vulnerabilities & CVEs\n"
        "/news  - General Cybersecurity News\n"
        "/blogs - Posts from Security Blogs\n"
        "/tech  - Tech News and How-Tos\n"
        "/red_blue_team - Red & Blue Team Tactics\n"
        "/tools - Latest Security Tools\n"
        "/threat_intel_feed - Threat Intelligence Reports\n"
    )
    await update.message.reply_text(message)

async def vuln(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching latest vulnerabilities and CVEs...")
    items = fetch_cve(5)
    for url in [RSS_FEEDS['exploitdb'], RSS_FEEDS['bleepingcomputer']]:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No new vulnerabilities or CVEs found.")

async def news(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching latest cybersecurity news...")
    feeds = [RSS_FEEDS['thehackersnews'], RSS_FEEDS['securityweek'], RSS_FEEDS['cybersecuritynews'], RSS_FEEDS['darkreading']]
    items = []
    for url in feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No news found.")

async def blogs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching latest blog posts...")
    feeds = [RSS_FEEDS['invicti'], RSS_FEEDS['huggingface'], RSS_FEEDS['xda_security']]
    items = []
    for url in feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No new blog posts found.")

async def tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching tech updates...")
    tech_feeds = [
        RSS_FEEDS['kali'], RSS_FEEDS['gbhackers'], RSS_FEEDS['hindustan_howto'],
        RSS_FEEDS['hindustan_mobile_reviews'], RSS_FEEDS['hindustan_mobile_news'],
        RSS_FEEDS['hindustan_laptops_news'], RSS_FEEDS['gadgets360_latest'],
        RSS_FEEDS['techspot'], RSS_FEEDS['techradar'], RSS_FEEDS['pureinfotech'],
        RSS_FEEDS['androidauthority_feed']
    ]
    items = []
    for url in tech_feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No tech RSS updates found.")
    
    # Send checkout links
    checkout_message = "Also, check out these sites manually:\n"
    for name, link in TECH_CHECKOUT_LINKS.items():
        checkout_message += f"- [{name}]({link})\n"
    await update.message.reply_text(checkout_message, parse_mode="Markdown", disable_web_page_preview=True)

async def red_blue_team(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching Red & Blue team content...")
    feeds = [RSS_FEEDS['hackthebox_red'], RSS_FEEDS['hackthebox_blue']]
    items = []
    for url in feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No Red/Blue team content found.")

async def tools(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching latest tools...")
    feeds = [RSS_FEEDS['kitploit'], RSS_FEEDS['secpod']]
    items = []
    for url in feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No new tools found.")

async def threat_intel_feed(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching threat intelligence feeds...")
    feeds = [
        RSS_FEEDS['dfir_report'], RSS_FEEDS['checkpoint'], RSS_FEEDS['socprime'],
        RSS_FEEDS['juniper'], RSS_FEEDS['portswigger'], RSS_FEEDS['unit42']
    ]
    items = []
    for url in feeds:
        items.extend(fetch_rss(url))
    if items:
        for item in items:
            await update.message.reply_text(item, parse_mode="Markdown")
    else:
        await update.message.reply_text("No new threat intel found.")

# --- Main Application ---
def main():
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Register handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("vuln", vuln))
    app.add_handler(CommandHandler("news", news))
    app.add_handler(CommandHandler("blogs", blogs))
    app.add_handler(CommandHandler("tech", tech))
    app.add_handler(CommandHandler("red_blue_team", red_blue_team))
    app.add_handler(CommandHandler("tools", tools))
    app.add_handler(CommandHandler("threat_intel_feed", threat_intel_feed))
    
    # Start the Bot
    logging.info("Starting bot...")
    app.run_polling()

if __name__ == '__main__':
    main()

