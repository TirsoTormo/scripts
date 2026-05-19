import datetime
import os
import logging
from logging.handlers import RotatingFileHandler
from app.handlers.base import BaseHandler
from app.models.event import Event
from app.core.config import settings

class LoggerHandler(BaseHandler):
    """
    Logger Handler that records structured, formatted logs of incoming 
    events into a central local text file.
    Uses a RotatingFileHandler to limit disk utilization and prevent storage exhaustion.
    """
    def __init__(self, log_filename: str = "infra_events.log"):
        super().__init__(name="FileLogger")
        self.log_path = os.path.abspath(settings.LOG_FILE_INFRA)
        
        # Initialize event logger dedicated to infrastructure logs
        self.event_logger = logging.getLogger("gateway.infra_events")
        self.event_logger.setLevel(logging.INFO)
        self.event_logger.propagate = False  # Keep clean separating from console stdouts
        
        # Setup rotating file logic if not previously initialized
        if not self.event_logger.handlers:
            # Enforce user configured file capacity and rotating backup boundaries
            rotating_handler = RotatingFileHandler(
                self.log_path,
                maxBytes=settings.LOG_ROTATION_MAX_BYTES,
                backupCount=settings.LOG_ROTATION_BACKUP_COUNT,
                encoding="utf-8"
            )
            # Use raw message log formatting
            formatter = logging.Formatter("%(message)s")
            rotating_handler.setFormatter(formatter)
            self.event_logger.addHandler(rotating_handler)

    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        try:
            readable_date = datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            dup_tag = f" [DUPLICATE x{duplicate_count}]" if is_duplicate else ""
            
            # Construct standard log line format
            log_line = (
                f"[{readable_date}] [{event.severity.value}]{dup_tag} "
                f"[{event.source}] {event.service}: {event.message}"
            )
            
            # Thread-safe log rotation dispatch
            self.event_logger.info(log_line)
                
            self.logger.info(f"Event logged successfully with log rotation: {event.source} -> {event.service}")
            
        except Exception as e:
            self.logger.error(f"Failed to write to local log file: {e}")
