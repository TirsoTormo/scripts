from app.handlers.logger import LoggerHandler
from app.handlers.telegram import TelegramHandler
from app.handlers.discord import DiscordHandler
from app.handlers.slack import SlackHandler
from app.handlers.ssh import SSHRemediationHandler
from app.handlers.docker_healer import DockerHealingHandler
from app.handlers.k8s_healer import KubernetesHealingHandler

# Singletons of handlers
logger_handler = LoggerHandler()
telegram_notifier = TelegramHandler()
discord_notifier = DiscordHandler()
slack_notifier = SlackHandler()
ssh_remediator = SSHRemediationHandler()
docker_healer = DockerHealingHandler()
k8s_healer = KubernetesHealingHandler()

# Map handlers by name for dynamic resolving
HANDLERS_MAP = {
    "logger": logger_handler,
    "telegram": telegram_notifier,
    "discord": discord_notifier,
    "slack": slack_notifier,
    "ssh": ssh_remediator,
    "docker": docker_healer,
    "k8s": k8s_healer
}

__all__ = [
    "HANDLERS_MAP",
    "telegram_notifier",
    "discord_notifier",
    "slack_notifier",
    "ssh_remediator",
    "docker_healer",
    "k8s_healer"
]
