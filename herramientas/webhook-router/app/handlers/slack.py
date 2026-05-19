import datetime
from app.handlers.base import BaseHandler
from app.models.event import Event
from app.core.config import settings

class SlackHandler(BaseHandler):
    """
    Asynchronous Handler to dispatch formatted alerts to Slack
    using secure Incoming Webhooks and Slack Block Kit layout.
    Utilizes exponential backoff safe POST requests.
    """
    def __init__(self):
        super().__init__(name="SlackNotifier")
        self.webhook_url = settings.SLACK_WEBHOOK_URL

    def _get_attachment_color(self, severity: str) -> str:
        if severity == "CRITICAL":
            return "#FF0000"  # Red
        elif severity == "WARNING":
            return "#FFA500"  # Orange
        return "#0000FF"       # Blue

    def _build_slack_payload(self, event: Event) -> dict:
        readable_date = datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        color = self._get_attachment_color(event.severity.value)
        
        # Structure block payload under attachments to support sidebar color indicators
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Webhook Gateway Alert: {event.severity.value}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*🖥️ Source Host:* `{event.source}`"},
                    {"type": "mrkdwn", "text": f"*⚙️ Service:* `{event.service}`"},
                    {"type": "mrkdwn", "text": f"*🏷️ Severity:* *{event.severity.value}*"},
                    {"type": "mrkdwn", "text": f"*📅 Date/Time:* `{readable_date}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*💬 Message Description:* \n> {event.message}"
                }
            }
        ]

        # Append additional troubleshooting sections if available in event metadata
        metadata = event.metadata
        if metadata:
            meta_fields = []
            if "docker_container" in metadata:
                meta_fields.append({"type": "mrkdwn", "text": f"*🐳 Docker Container:* `{metadata['docker_container']}`"})
            if "ssh_host_override" in metadata:
                meta_fields.append({"type": "mrkdwn", "text": f"*🌐 Rescue host:* `{metadata['ssh_host_override']}`"})
            if "failing_streak" in metadata:
                meta_fields.append({"type": "mrkdwn", "text": f"*⚡ Failure Streak:* `{metadata['failing_streak']}`"})
            
            if meta_fields:
                blocks.append({
                    "type": "section",
                    "fields": meta_fields
                })

            if "logs" in metadata:
                log_snippet = str(metadata["logs"])[:600]
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*📋 Diagnostic Logs Snippet:*\n```\n{log_snippet}\n```"
                    }
                })

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }
        return payload

    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        if is_duplicate:
            self.logger.info(f"Deduplication: Suppressing Slack alert for {event.source}:{event.service}.")
            return

        payload = self._build_slack_payload(event)

        if not settings.is_slack_configured:
            # Console simulation mode
            self.logger.info(
                f"[SLACK SIMULATION] Webhook URL not configured.\n"
                f"Generated Slack blocks:\n"
                f"   Blocks: {payload['attachments'][0]['blocks']}\n"
            )
            return

        try:
            # Send using safe_post featuring backoff retries
            response = await self.safe_post(self.webhook_url, payload)
            if response.status_code == 200:
                self.logger.info("Slack alert successfully dispatched.")
            else:
                self.logger.error(f"Slack Webhook returned non-success status ({response.status_code}): {response.text}")
        except Exception as e:
            self.logger.error(f"Network error trying to connect to Slack Webhook: {e}")
