import os
import yaml
import socket
import asyncssh
import logging
import time
from logging.handlers import RotatingFileHandler
from app.handlers.base import BaseHandler
from app.models.event import Event
from app.core.config import settings
from app.core.database import db_manager

class SSHRemediationHandler(BaseHandler):
    """
    Automated SSH Remediation Handler using AsyncSSH (Non-blocking).
    Connects to target server nodes to safely orchestrate recovery shell
    commands for critical alerts.
    Supports hosts.yaml dynamic alias resolution, private key passphrases,
    SQLite persistence logging, and rotating text log files.
    """
    def __init__(self, log_filename: str = "remediation_history.log"):
        super().__init__(name="SSHRemediator")
        # Direct remediation history logs to the data folder
        self.log_path = os.path.abspath(settings.LOG_FILE_REMEDIATION)
        
        # Setup specific rotating file logger for remediation text histories
        self.history_logger = logging.getLogger("gateway.remediation_history")
        self.history_logger.setLevel(logging.INFO)
        self.history_logger.propagate = False
        
        if not self.history_logger.handlers:
            rotating_handler = RotatingFileHandler(
                self.log_path,
                maxBytes=settings.LOG_ROTATION_MAX_BYTES,
                backupCount=settings.LOG_ROTATION_BACKUP_COUNT,
                encoding="utf-8"
            )
            formatter = logging.Formatter("%(message)s")
            rotating_handler.setFormatter(formatter)
            self.history_logger.addHandler(rotating_handler)
        
        # Default mapping from services to recovery actions
        self.remediation_rules = {
            "docker-postgres": "docker start postgres || docker restart postgres",
            "docker-nginx": "docker restart nginx",
            "docker-apache": "docker restart apache",
            "mysql": "sudo systemctl restart mysql",
            "nginx": "sudo systemctl restart nginx",
            "apache2": "sudo systemctl restart apache2",
            "cron": "sudo systemctl restart cron"
        }

    def _resolve_host_alias(self, alias: str) -> dict:
        """Resolves target host details using hosts.yaml if present on disk."""
        hosts_path = "hosts.yaml"
        if os.path.exists(hosts_path):
            try:
                with open(hosts_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    hosts_map = data.get("hosts", {})
                    if alias in hosts_map:
                        self.logger.info(f"Resolved host alias '{alias}' securely via {hosts_path}")
                        return hosts_map[alias]
            except Exception as e:
                self.logger.error(f"Failed to read hosts config from {hosts_path}: {e}")
        return {}

    def _get_remediation_command(self, event: Event) -> str:
        """Resolves the shell command to execute on the target server."""
        if event.metadata and "remediation_cmd" in event.metadata:
            return event.metadata["remediation_cmd"]

        if event.metadata and "docker_container" in event.metadata:
            container = event.metadata["docker_container"]
            return f"docker restart {container} || docker start {container}"

        service_clean = event.service.lower().strip()
        if service_clean in self.remediation_rules:
            return self.remediation_rules[service_clean]
        
        if "docker-" in service_clean:
            container_name = service_clean.replace("docker-", "")
            return f"docker restart {container_name} || docker start {container_name}"
            
        return f"sudo systemctl status {event.service} --no-pager || echo 'Service not managed by systemd'"

    async def execute(self, event: Event, is_duplicate: bool = False, duplicate_count: int = 0) -> None:
        if event.severity.value != "CRITICAL":
            return
            
        if is_duplicate:
            self.logger.info(f"Deduplication: Suppressing SSH remediation for {event.source}:{event.service}.")
            return

        # Core command and credentials parsing
        command = self._get_remediation_command(event)
        ssh_host = settings.SSH_HOST
        ssh_user = settings.SSH_USERNAME
        ssh_port = settings.SSH_PORT

        # Evaluate if custom overrides are specified in client metadata
        if event.metadata:
            if "ssh_host_override" in event.metadata:
                override_alias = event.metadata["ssh_host_override"]
                # 1. Attempt to resolve host alias from local hosts.yaml registry
                resolved = self._resolve_host_alias(override_alias)
                if resolved:
                    ssh_host = resolved.get("host", ssh_host)
                    ssh_port = resolved.get("port", ssh_port)
                    ssh_user = resolved.get("username", ssh_user)
                else:
                    # 2. Fallback: Treat override_alias directly as an IP/Domain coordinate
                    ssh_host = override_alias
                    if "ssh_user_override" in event.metadata:
                        ssh_user = event.metadata["ssh_user_override"]

        # Run in console simulation mode if target host configuration is empty
        if not ssh_host:
            sim_host = ssh_host or "SimulatedHost"
            self.logger.info(
                f"[SSH SIMULATION] Simulated connection to {ssh_user or 'admin'}@{sim_host}:{ssh_port}\n"
                f"Command that would have been executed:\n"
                f"   $ {command}\n"
            )
            # Log simulation success as a 0 exit status inside local SQLite (async)
            await db_manager.add_remediation_record(event.source, event.service, command, 0, "SIMULATION SUCCESS", sim_host)
            self._save_remediation_history_log(event, command, 0, "SIMULATION SUCCESS", sim_host)
            return

        self.logger.info(f"Connecting to remote target {ssh_host}:{ssh_port} via SSH as user '{ssh_user}'...")
        
        try:
            connection_kwargs = {
                "host": ssh_host,
                "port": ssh_port,
                "username": ssh_user,
                "known_hosts": None # Disable host key check to match Paramiko auto-add policy
            }
            
            # Determine cryptographic key decryption (Key-based vs Password auth)
            if settings.SSH_PRIVATE_KEY_PATH:
                key_path = os.path.expanduser(settings.SSH_PRIVATE_KEY_PATH)
                if os.path.exists(key_path):
                    connection_kwargs["client_keys"] = [key_path]
                    if settings.SSH_PRIVATE_KEY_PASSPHRASE:
                        connection_kwargs["passphrase"] = settings.SSH_PRIVATE_KEY_PASSPHRASE
                else:
                    self.logger.error(f"SSH private key file not found at: {key_path}")
                    if settings.SSH_PASSWORD:
                        connection_kwargs["password"] = settings.SSH_PASSWORD
            elif settings.SSH_PASSWORD:
                connection_kwargs["password"] = settings.SSH_PASSWORD

            async with asyncssh.connect(**connection_kwargs) as conn:
                self.logger.info(f"SSH Session established. Executing recovery command: '{command}'")
                result = await conn.run(command, timeout=30.0)
                exit_status = result.exit_status or 0
                stdout_str = result.stdout.strip()
                stderr_str = result.stderr.strip()
                
                # Record execution outcome to SQLite & Rotating Logs (async)
                if exit_status == 0:
                    self.logger.info(f"SSH Command executed successfully (Exit Code 0).")
                    await db_manager.add_remediation_record(event.source, event.service, command, exit_status, stdout_str, ssh_host)
                    self._save_remediation_history_log(event, command, exit_status, stdout_str, ssh_host)
                else:
                    self.logger.warning(f"SSH Command failed with non-zero exit code ({exit_status}).")
                    error_details = f"ERROR: {stderr_str}\nSTDOUT: {stdout_str}"
                    await db_manager.add_remediation_record(event.source, event.service, command, exit_status, error_details, ssh_host)
                    self._save_remediation_history_log(event, command, exit_status, error_details, ssh_host)

        except asyncssh.PermissionDenied:
            err_msg = f"SSH Authentication failed for user '{ssh_user}'"
            self.logger.error(f"{err_msg} on host {ssh_host}")
            await db_manager.add_remediation_record(event.source, event.service, command, -1, err_msg, ssh_host)
            self._save_remediation_history_log(event, command, -1, err_msg, ssh_host)
        except OSError as e:
            err_msg = f"Network connection / timeout error: {e}"
            self.logger.error(f"{err_msg} trying to reach {ssh_host}")
            await db_manager.add_remediation_record(event.source, event.service, command, -2, err_msg, ssh_host)
            self._save_remediation_history_log(event, command, -2, err_msg, ssh_host)
        except Exception as e:
            err_msg = f"Unexpected remote execution failure: {e}"
            self.logger.error(err_msg)
            await db_manager.add_remediation_record(event.source, event.service, command, -3, err_msg, ssh_host)
            self._save_remediation_history_log(event, command, -3, err_msg, ssh_host)

    def _save_remediation_history_log(self, event: Event, command: str, status: int, result: str, host: str) -> None:
        """Logs execution history records to a standard rotating log file."""
        try:
            log_block = (
                f"=== REMEDIATION: {event.source} | Host: {host} | Service: {event.service} ===\n"
                f"Command Executed: {command}\n"
                f"Exit Status: {status}\n"
                f"Execution Output:\n{result}\n"
                f"==================================================\n"
            )
            self.history_logger.info(log_block)
        except Exception as e:
            self.logger.error(f"Failed to write to remediation history rotating log file: {e}")
