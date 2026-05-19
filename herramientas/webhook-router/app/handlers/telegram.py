import datetime
from app.handlers.base import BaseHandler
from app.models.event import Event
from app.core.config import settings

class TelegramHandler(BaseHandler):
    """
    Asynchronous Handler to dispatch alerts to a specified Telegram Bot Chat.
    Enriches format using Markdown and severities mapping to emojis.
    Utilizes exponential backoff safe POST requests.
    """
    def __init__(self):
        super().__init__(name="TelegramNotifier")
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID

    def _get_severity_label(self, severity: str) -> str:
        if severity == "CRITICAL":
            return "🛑 CRITICAL"
        elif severity == "WARNING":
            return "⚠️ WARNING"
        return "ℹ️ INFO"

    def _build_markdown_message(self, event: Event) -> str:
        readable_date = datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        severity_label = self._get_severity_label(event.severity.value)
        
        message = (
            f"🚨 *INFRASTRUCTURE ALERT DETECTED*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🖥️ *Source Host:* `{event.source}`\n"
            f"⚙️ *Service:* `{event.service}`\n"
            f"🏷️ *Severity:* *{severity_label}*\n"
            f"📅 *Timestamp:* `{readable_date}`\n\n"
            f"💬 *Description:* \n"
            f"> {event.message}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 _Sent by Webhook Gateway Router_"
        )
        return message

    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        if is_duplicate:
            self.logger.info(f"Deduplication: Suppressing Telegram alert for {event.source}:{event.service}.")
            return

        markdown_message = self._build_markdown_message(event)

        if not settings.is_telegram_configured:
            # Console simulation mode
            self.logger.info(
                f"[TELEGRAM SIMULATION]\n"
                f"Generated Telegram message:\n"
                f"{markdown_message}\n"
            )
            return

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": markdown_message,
            "parse_mode": "Markdown"
        }

        try:
            # Send using safe_post featuring backoff retries
            response = await self.safe_post(url, payload)
            if response.status_code == 200:
                self.logger.info(f"Telegram alert successfully dispatched to chat {self.chat_id}")
            else:
                self.logger.error(
                    f"Telegram API returned non-200 (Status {response.status_code}): {response.text}"
                )
        except Exception as e:
            self.logger.error(f"Network error trying to connect to Telegram API: {e}")
