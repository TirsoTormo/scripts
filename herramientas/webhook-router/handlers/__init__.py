from handlers.logger import LoggerHandler
from handlers.telegram import TelegramHandler
from handlers.discord import DiscordHandler
from handlers.slack import SlackHandler
from handlers.ssh import SSHRemediationHandler
from handlers.docker_healer import DockerHealingHandler
from handlers.k8s_healer import KubernetesHealingHandler

# Instantiate global singletons
file_logger = LoggerHandler()
telegram_notifier = TelegramHandler()
discord_notifier = DiscordHandler()
slack_notifier = SlackHandler()
ssh_remediator = SSHRemediationHandler()
docker_healer = DockerHealingHandler()
k8s_healer = KubernetesHealingHandler()

# Map handler identifier tags to active singletons for dynamic routing
HANDLERS_MAP = {
    "logger": file_logger,
    "telegram": telegram_notifier,
    "discord": discord_notifier,
    "slack": slack_notifier,
    "ssh": ssh_remediator,
    "docker_healer": docker_healer,
    "k8s_healer": k8s_healer
}

# Export list containing all active system handlers
ALL_HANDLERS = [
    file_logger,
    telegram_notifier,
    discord_notifier,
    slack_notifier,
    ssh_remediator,
    docker_healer,
    k8s_healer
]

__all__ = [
    "file_logger",
    "telegram_notifier",
    "discord_notifier",
    "slack_notifier",
    "ssh_remediator",
    "docker_healer",
    "k8s_healer",
    "HANDLERS_MAP",
    "ALL_HANDLERS"
]
