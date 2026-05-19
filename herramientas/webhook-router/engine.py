import time
import os
import yaml
import logging
from typing import Dict, Tuple, List
from models import Event, EventSeverity
from config import settings
from database import db_manager
from handlers import HANDLERS_MAP, telegram_notifier, discord_notifier, slack_notifier

logger = logging.getLogger("webhook-gateway.engine")

class AlertDeduplicator:
    """
    Prevents alert storms by tracking duplicate events persistently inside SQLite.
    Saves and reads states from the local DB, enduring server updates and reboots.
    """
    def __init__(self):
        self.window_seconds = settings.DEDUPLICATION_WINDOW_SECONDS

    def check_and_update(self, event: Event) -> Tuple[bool, int]:
        """
        Validates if an event is a duplicate. Fetches and updates SQLite persistence cache.
        
        Returns:
            Tuple[bool, int]: (is_duplicate, current_count)
        """
        key = event.get_deduplication_key()
        now = time.time()

        # Query SQLite persistent database cache
        entry = db_manager.get_deduplication_entry(key)

        if entry:
            # Check if this occurrence falls within the sliding deduplication window
            if now - entry["first_seen"] < self.window_seconds:
                new_count = entry["count"] + 1
                db_manager.save_deduplication_entry(key, entry["first_seen"], now, new_count)
                logger.debug(f"Persistent duplicate event recorded for '{key}'. Count: {new_count}")
                return True, new_count
            else:
                # Sliding window expired, reset tracking parameters in SQLite
                logger.info(f"Deduplication window expired for '{key}'. Resetting counter.")
                db_manager.save_deduplication_entry(key, now, now, 1)
                return False, 1
        else:
            # First time observing this specific alert event combination
            db_manager.save_deduplication_entry(key, now, now, 1)
            return False, 1

    def clear_cache(self):
        """Clears all deduplication records in the SQLite database."""
        db_manager.clear_deduplication_cache()


class DigestCollector:
    """
    Buffers lower priority alerts (INFO and WARNING) to prepare 
    scheduled, grouped summary reports instead of dispatching immediately.
    """
    def __init__(self):
        self.accumulated_events: List[Event] = []

    def add_event(self, event: Event):
        self.accumulated_events.append(event)
        logger.info(f"Buffered {event.severity.value} alert for '{event.service}' to the periodic digest.")

    def get_and_clear(self) -> List[Event]:
        events = list(self.accumulated_events)
        self.accumulated_events.clear()
        return events


class EventRouter:
    """
    Dynamic routing engine. Loads customizable rules from rules.yaml
    and schedules actions based on incoming event characteristics.
    """
    def __init__(self):
        self.deduplicator = AlertDeduplicator()
        self.digest_collector = DigestCollector()
        self.rules: List[dict] = []
        self.load_rules()

    def load_rules(self):
        """Loads routing rules from rules.yaml dynamically."""
        rules_path = "rules.yaml"
        if os.path.exists(rules_path):
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    self.rules = data.get("rules", [])
                logger.info(f"Successfully loaded {len(self.rules)} dynamic rules from {rules_path}")
            except Exception as e:
                logger.error(f"Error parsing {rules_path}: {e}. Falling back to default routing in memory.")
                self._load_fallback_rules()
        else:
            logger.warning(f"{rules_path} not found. Operating with fallback default rules.")
            self._load_fallback_rules()

    def _load_fallback_rules(self):
        """Initializes default, secure rules if rules.yaml is missing."""
        self.rules = [
            {
                "name": "Default Info",
                "match": {"severity": "INFO"},
                "handlers": ["logger"]
            },
            {
                "name": "Default Warning",
                "match": {"severity": "WARNING"},
                "handlers": ["logger", "telegram", "slack", "discord"]
            },
            {
                "name": "Default Critical",
                "match": {"severity": "CRITICAL"},
                "handlers": ["logger", "telegram", "slack", "discord", "ssh"]
            }
        ]

    def _match_rule(self, rule: dict, event: Event) -> bool:
        """Compares incoming event fields against match criteria defined in rules."""
        match_criteria = rule.get("match", {})
        if not match_criteria:
            return False
            
        for key, val in match_criteria.items():
            if key == "severity":
                if event.severity.value != val.upper():
                    return False
            elif key == "service":
                if event.service.lower() != val.lower():
                    return False
            elif key == "source":
                if event.source.lower() != val.lower():
                    return False
            elif key == "platform":
                event_platform = event.metadata.get("platform", "").lower() if event.metadata else ""
                if event_platform != val.lower():
                    return False
        return True

    async def route_event(self, event: Event) -> Dict[str, any]:
        """
        Routes the event through rule matches and executes handlers in the background.
        Handles persistent deduplication and periodic digest grouping.
        """
        # 1. Update processed event telemetry counter inside SQLite
        db_manager.increment_event_counter(event.severity.value)

        # 2. Check if event is a duplicate in the persistent SQLite cache
        is_duplicate, duplicate_count = self.deduplicator.check_and_update(event)
        
        # 3. Accumulate non-critical events for periodic summary digest reports
        if event.severity in [EventSeverity.INFO, EventSeverity.WARNING] and not is_duplicate:
            self.digest_collector.add_event(event)

        # 4. Locate matching custom rules
        matched_rules = []
        handlers_to_trigger = set()
        
        for rule in self.rules:
            if self._match_rule(rule, event):
                matched_rules.append(rule["name"])
                
                # Dynamic override injection (direct command overrides specified inside YAML rule)
                if "remediation_cmd_override" in rule:
                    if not event.metadata:
                        event.metadata = {}
                    if "remediation_cmd" not in event.metadata:
                        event.metadata["remediation_cmd"] = rule["remediation_cmd_override"]
                
                for handler_name in rule.get("handlers", []):
                    handlers_to_trigger.add(handler_name)

        # Safety Fallback: Ensure at least local file logging executes
        if not handlers_to_trigger:
            handlers_to_trigger.add("logger")
            matched_rules.append("Safety Fallback Logger")

        # 5. Asynchronously execute all scheduled handlers
        executed_actions = []
        for handler_name in handlers_to_trigger:
            handler = HANDLERS_MAP.get(handler_name.lower())
            if handler:
                try:
                    await handler.execute(event, is_duplicate=is_duplicate, duplicate_count=duplicate_count)
                    executed_actions.append(handler_name)
                except Exception as e:
                    logger.error(f"Critical execution error inside handler '{handler_name}': {e}")
            else:
                logger.warning(f"Requested handler '{handler_name}' is not registered.")

        return {
            "status": "processed",
            "matched_rules": matched_rules,
            "is_duplicate": is_duplicate,
            "duplicate_count": duplicate_count,
            "handlers_executed": executed_actions
        }


# Global engine singleton
router_engine = EventRouter()


# ======================================================================
# SCHEDULED PERIODIC STATUS DIGEST SCRIPT (APScheduler Job)
# ======================================================================

async def send_periodic_digest():
    """
    Executes periodically via APScheduler.
    Aggregates buffered lower severity events (INFO, WARNING)
    and broadcasts a clean status summary report to active chat channels.
    """
    events = router_engine.digest_collector.get_and_clear()
    if not events:
        logger.info("Periodic Digest: No accumulated events in this window.")
        return

    logger.info(f"Periodic Digest: Dispatching status report containing {len(events)} events...")
    
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Construct a highly formatted status report
    report_text = (
        f"📊 *PERIODIC INFRASTRUCTURE STATUS DIGEST*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📅 *Generated:* `{current_time}`\n"
        f"🗂️ *Accumulated Alerts:* {len(events)} (Severity INFO/WARNING)\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    )
    
    for idx, ev in enumerate(events, 1):
        severity_label = "⚠️ WARNING" if ev.severity == EventSeverity.WARNING else "ℹ️ INFO"
        report_text += (
            f"*{idx}. {severity_label}* on `{ev.source}`\n"
            f" ⚙️ *Service:* `{ev.service}`\n"
            f" 💬 *Message:* {ev.message}\n"
            f" 🕐 *Time:* `{time.strftime('%H:%M:%S', time.localtime(ev.timestamp))}`\n"
            f"──────────────────────────\n"
        )
        
    report_text += f"\n🤖 _Report aggregated and sent by Webhook Gateway_"

    # Construct dummy Event object to route the digest report through chat handlers
    digest_event = Event(
        token=settings.GATEWAY_TOKEN,
        source="Webhook-Gateway",
        service="Digest-Engine",
        severity=EventSeverity.INFO,
        message=report_text,
        timestamp=int(time.time()),
        metadata={"is_digest_report": True}
    )

    # Dispatch to active communication adapters
    try:
        await telegram_notifier.execute(digest_event, is_duplicate=False)
    except Exception as e:
        logger.error(f"Failed to dispatch digest report to Telegram: {e}")
        
    try:
        await discord_notifier.execute(digest_event, is_duplicate=False)
    except Exception as e:
        logger.error(f"Failed to dispatch digest report to Discord: {e}")
        
    try:
        await slack_notifier.execute(digest_event, is_duplicate=False)
    except Exception as e:
        logger.error(f"Failed to dispatch digest report to Slack: {e}")
        
    logger.info("Periodic digest status report dispatched successfully.")
