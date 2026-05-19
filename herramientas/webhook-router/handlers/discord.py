import datetime
from handlers.base import BaseHandler
from models import Event
from config import settings

class DiscordHandler(BaseHandler):
    """
    Asynchronous Handler to dispatch rich Discord Embed alerts
    using secure Discord incoming Webhooks.
    Utilizes exponential backoff safe POST requests.
    """
    def __init__(self):
        super().__init__(name="DiscordNotifier")
        self.webhook_url = settings.DISCORD_WEBHOOK_URL

    def _get_embed_color(self, severity: str) -> int:
        # Hexadecimal colors parsed to decimal integer value
        if severity == "CRITICAL":
            return 15158332  # Red (#E74C3C)
        elif severity == "WARNING":
            return 15105570  # Orange (#E67E22)
        return 3447003       # Blue (#3498DB)

    def _build_discord_embed(self, event: Event) -> dict:
        readable_date = datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        color = self._get_embed_color(event.severity.value)
        
        # Standard structural fields
        fields = [
            {"name": "🖥️ Source Host", "value": f"`{event.source}`", "inline": True},
            {"name": "⚙️ Service", "value": f"`{event.service}`", "inline": True},
            {"name": "📅 Timestamp", "value": f"`{readable_date}`", "inline": False}
        ]
        
        # Enrich embeds if metadata contains troubleshooting logs or Docker details
        metadata = event.metadata
        if metadata:
            if "docker_container" in metadata:
                fields.append({"name": "🐳 Docker Container", "value": f"`{metadata['docker_container']}`", "inline": True})
            if "ssh_host_override" in metadata:
                fields.append({"name": "🌐 Remediation Target", "value": f"`{metadata['ssh_host_override']}`", "inline": True})
            if "failing_streak" in metadata:
                fields.append({"name": "⚡ Failure Streak", "value": f"`{metadata['failing_streak']}`", "inline": True})
            if "logs" in metadata:
                # Truncate container logs to fit within Discord limits (max 1024 characters per field value)
                log_snippet = str(metadata["logs"])[:800]
                fields.append({"name": "📋 Diagnostics Logs", "value": f"```log\n{log_snippet}\n```", "inline": False})

        embed = {
            "title": f"🚨 Infrastructure Alert: {event.severity.value}",
            "description": f"**Message Details:**\n{event.message}",
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Webhook Gateway Server • Active Auto-Remediation"
            }
        }
        return embed

    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        if is_duplicate:
            self.logger.info(f"Deduplication: Suppressing Discord alert for {event.source}:{event.service}.")
            return

        embed = self._build_discord_embed(event)
        payload = {"embeds": [embed]}

        if not settings.is_discord_configured:
            # Console simulation mode
            self.logger.info(
                f"[DISCORD SIMULATION] Webhook URL not set.\n"
                f"Generated Discord Embed payload:\n"
                f"   Title: {embed['title']}\n"
                f"   Description: {embed['description']}\n"
                f"   Fields: {embed['fields']}\n"
            )
            return

        try:
            # Send using safe_post featuring backoff retries
            response = await self.safe_post(self.webhook_url, payload)
            if response.status_code in [200, 204]:
                self.logger.info("Discord alert embed successfully dispatched.")
            else:
                self.logger.error(f"Discord Webhook returned non-success status ({response.status_code}): {response.text}")
        except Exception as e:
            self.logger.error(f"Network error trying to connect to Discord Webhook: {e}")
