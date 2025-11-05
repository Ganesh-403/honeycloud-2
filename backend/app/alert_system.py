"""
Alert System for HoneyCloud-X
Sends Telegram alerts for critical/malicious events
"""
import requests
import logging

logger = logging.getLogger(__name__)

# ====================================
# TELEGRAM CONFIGURATION
# ====================================
# TODO: Replace with your actual Telegram bot token and chat ID
TELEGRAM_BOT_TOKEN = "8255931524:AAHTQ0tJ5OCa7d1MKCraMrispfjgAVMjU4s"  # <-- Paste your bot token here
TELEGRAM_CHAT_ID = "1171633257"      # <-- Paste your chat ID here


def send_telegram_alert(message: str) -> bool:
    """
    Send alert message to Telegram bot.
    
    Args:
        message: The alert message text
        
    Returns:
        True if sent successfully, False otherwise
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(url, data=payload, timeout=5)
        if response.status_code == 200:
            logger.info("✅ Telegram alert sent successfully")
            return True
        else:
            logger.error(f"❌ Failed to send Telegram alert: {response.text}")
            return False
    except Exception as e:
        logger.error(f"❌ Exception while sending Telegram alert: {e}")
        return False


def send_telegram_document(file_path: str, caption: str = "") -> bool:
    """
    Send a file (PDF/CSV) to Telegram bot.
    
    Args:
        file_path: Path to the file to send
        caption: Optional caption for the file
        
    Returns:
        True if sent successfully, False otherwise
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    
    try:
        with open(file_path, "rb") as file:
            files = {"document": file}
            data = {"chat_id": TELEGRAM_CHAT_ID, "caption": caption}
            response = requests.post(url, data=data, files=files, timeout=10)
            
        if response.status_code == 200:
            logger.info(f"✅ File sent to Telegram: {file_path}")
            return True
        else:
            logger.error(f"❌ Failed to send file: {response.text}")
            return False
    except Exception as e:
        logger.error(f"❌ Exception while sending file: {e}")
        return False


def format_alert_message(event: dict) -> str:
    """
    Format an attack event into a readable alert message.
    
    Args:
        event: Dictionary containing attack event data
        
    Returns:
        Formatted message string
    """
    message = (
        f"🚨 *HoneyCloud-X Security Alert*\n\n"
        f"*Service:* {event.get('service', 'Unknown')}\n"
        f"*Source IP:* `{event.get('source_ip', 'Unknown')}`\n"
        f"*Username:* `{event.get('username', 'N/A')}`\n"
        f"*Severity:* *{event.get('severity', 'Unknown')}*\n"
        f"*AI Classification:* {event.get('ai_label', 'Unknown')}\n"
        f"*Threat Score:* {event.get('threat_score', 0):.2f}\n"
        f"*Timestamp:* {event.get('timestamp', 'Unknown')}\n"
    )
    
    if event.get('command'):
        message += f"*Command:* `{event.get('command')}`\n"
    
    return message


def handle_attack_event(event: dict):
    """
    Process an attack event and send alerts if necessary.
    Automatically sends Telegram alerts for CRITICAL severity or malicious AI labels.
    
    Args:
        event: Dictionary containing attack event data
    """
    severity = event.get("severity", "").upper()
    ai_label = event.get("ai_label", "").lower()
    
    # Send alert for critical or malicious events
    if severity == "CRITICAL" or ai_label == "malicious":
        message = format_alert_message(event)
        
        sent = send_telegram_alert(message)
        if sent:
            logger.info(f"🚨 Critical alert sent for event {event.get('id')}")
        else:
            logger.warning(f"⚠️ Failed to send alert for event {event.get('id')}")
    else:
        logger.debug(f"Event {event.get('id')} not critical, no alert sent")
