import logging
import asyncio
import httpx
from abc import ABC, abstractmethod
from models import Event

# Configure default logging format for server actions
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("webhook-gateway")

class BaseHandler(ABC):
    """
    Abstract Base Class for all event handlers.
    Defines the contract for background task execution.
    Provides utility methods like safe, retrying async HTTP dispatches.
    """
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"handler.{name}")

    async def safe_post(self, url: str, payload: dict, max_retries: int = 3) -> httpx.Response:
        """
        Executes an asynchronous HTTP POST request utilizing exponential backoff retries.
        Protects against transient gateway timeouts and networking drops.
        """
        delay = 2.0  # Start with 2 seconds
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for attempt in range(1, max_retries + 1):
                try:
                    response = await client.post(url, json=payload)
                    if response.status_code in [200, 201, 204]:
                        return response
                    
                    self.logger.warning(
                        f"Post call returned status {response.status_code} "
                        f"(Attempt {attempt}/{max_retries}). Retrying in {delay}s..."
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Connection request failed: {e} "
                        f"(Attempt {attempt}/{max_retries}). Retrying in {delay}s..."
                    )
                
                # Sleep before retrying unless it is the last attempt
                if attempt < max_retries:
                    await asyncio.sleep(delay)
                    delay *= 2.0  # Exponential increase
            
            # Final attempt (will propagate exceptions if it fails)
            return await client.post(url, json=payload)

    @abstractmethod
    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        """
        Executes the assigned handler action asynchronously.
        
        Args:
            event (Event): The validated event instance.
            is_duplicate (bool): Indicates if the event has been deduplicated.
            duplicate_count (int): Counter of active sequential duplications.
        """
        pass
