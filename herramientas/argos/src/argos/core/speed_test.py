# pylint: disable=broad-exception-caught, too-many-locals, too-many-branches, too-many-statements, too-few-public-methods
"""
NetScanner - LAN Speed Test Module
Measures transfer speed between two computers on the local network
using direct TCP communication (without going out to the Internet).

Server Mode: Receives data and reports throughput.
Client Mode: Sends data to the server and measures speed in Mbps.
"""

import contextlib
import json
import socket
import struct
import threading
import time
from collections.abc import Callable

from argos.core.net_utils import is_private_ip

# Communication Protocol
HEADER_SIZE = 8  # 8 bytes for header (message size)
DEFAULT_PORT = 45678  # Default server port
BLOCK_SIZE = 65536  # 64 KB per transmission block
DEFAULT_DURATION = 10  # Default test duration in seconds
BUFFER_SIZE = 131072  # 128 KB receive buffer

# Control Messages
MSG_START = b"START___"
MSG_DONE = b"DONE____"
MSG_RESULT = b"RESULT__"


class SpeedTestServer:
    """
    TCP Server to receive data from client and measure throughput.
    Runs in a separate thread.
    """

    def __init__(self, port: int = DEFAULT_PORT, status_callback: Callable | None = None):
        self.port = port
        self.status_callback = status_callback
        self.server_socket = None
        self.running = False
        self._thread = None
        self.last_result = None

    def _log(self, msg: str):
        if self.status_callback:
            self.status_callback(msg)

    def start(self):
        """Starts the server in a separate thread."""
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        """Main server loop."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Large buffer for maximum performance
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 4)
            self.server_socket.settimeout(1.0)  # Timeout to allow clean stop
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(1)
            self._log(f"Server listening on port {self.port}...")
            self._log("Waiting for client connection...")
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self._log(f"Client connected: {client_addr[0]}:{client_addr[1]}")
                    self._handle_client(client_socket, client_addr)
                except TimeoutError:
                    continue
                except OSError:
                    break

        except OSError as e:
            self._log(f"Server error: {e}")
        finally:
            self._cleanup()

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """Handles a client connection and measures throughput."""
        try:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 4)

            # Wait for start signal
            start_msg = client_socket.recv(8)
            if start_msg != MSG_START:
                self._log("Invalid start message")
                return

            self._log("Speed test started — receiving data...")

            total_bytes = 0
            start_time = time.perf_counter()

            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                # Check for end signal
                if data[-8:] == MSG_DONE:
                    total_bytes += len(data) - 8
                    break

                total_bytes += len(data)

            elapsed = time.perf_counter() - start_time

            # Calculate results
            speed_mbps = (total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
            speed_mbs = total_bytes / (elapsed * 1_000_000) if elapsed > 0 else 0

            result = {
                "total_bytes": total_bytes,
                "duration_s": round(elapsed, 3),
                "speed_mbps": round(speed_mbps, 2),
                "speed_mbs": round(speed_mbs, 2),
                "client_ip": client_addr[0],
            }

            self.last_result = result

            # Send result to client
            result_json = json.dumps(result).encode("utf-8")
            client_socket.sendall(MSG_RESULT + struct.pack("!I", len(result_json)) + result_json)
            self._log(f"Test completed: {speed_mbps:.2f} Mbps ({speed_mbs:.2f} MB/s)")
        except Exception as e:
            self._log(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def stop(self):
        """Stops the server."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        self._cleanup()

    def _cleanup(self):
        """Closes the server socket."""
        if self.server_socket:
            with contextlib.suppress(Exception):
                self.server_socket.close()
            self.server_socket = None


class SpeedTestClient:
    """
    TCP Client to send data to server and measure throughput.
    """

    def __init__(self, status_callback: Callable | None = None):
        self.status_callback = status_callback

    def _log(self, msg: str):
        if self.status_callback:
            self.status_callback(msg)

    def run_test(
        self,
        server_ip: str,
        port: int = DEFAULT_PORT,
        duration: int = DEFAULT_DURATION,
        progress_callback: Callable | None = None,
    ) -> dict | None:
        """
        Runs a speed test against the server.

        Args:
            server_ip: Server IP
            port: Server port
            duration: Test duration in seconds
            progress_callback: Callback (msg, percentage)

        Returns:
            Dictionary with results or None if fails
        """
        # Verify it's a private IP (security: never go to Internet)
        if not is_private_ip(server_ip):
            self._log(f"ERROR: {server_ip} is not a private IP. Operation aborted.")
            return None
        sock = None
        try:
            self._log(f"Connecting to {server_ip}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE * 4)
            sock.settimeout(10)
            sock.connect((server_ip, port))
            self._log("Connection established")
            # Send start signal
            sock.sendall(MSG_START)
            # Generate random data block
            data_block = b"\x00" * BLOCK_SIZE
            self._log(f"Sending data for {duration} seconds...")
            total_bytes = 0
            start_time = time.perf_counter()
            last_report = start_time
            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= duration:
                    break
                try:
                    sock.sendall(data_block)
                    total_bytes += BLOCK_SIZE
                except (BrokenPipeError, ConnectionResetError):
                    break
                # Report progress every 0.5 seconds
                now = time.perf_counter()
                if now - last_report >= 0.5:
                    pct = elapsed / duration
                    current_speed = (total_bytes * 8) / (elapsed * 1_000_000)
                    if progress_callback:
                        progress_callback(
                            f"Current speed: {current_speed:.1f} Mbps", min(pct, 0.99)
                        )
                    last_report = now
            # Send end signal
            sock.sendall(MSG_DONE)
            total_elapsed = time.perf_counter() - start_time

            # Calculate client-side results
            client_speed_mbps = (
                (total_bytes * 8) / (total_elapsed * 1_000_000) if total_elapsed > 0 else 0
            )
            client_speed_mbs = total_bytes / (total_elapsed * 1_000_000) if total_elapsed > 0 else 0

            # Attempt to receive results from server
            server_result = None
            try:
                sock.settimeout(5)
                header = sock.recv(12)  # MSG_RESULT (8) + length (4)
                if header[:8] == MSG_RESULT:
                    result_len = struct.unpack("!I", header[8:12])[0]
                    result_data = b""
                    while len(result_data) < result_len:
                        chunk = sock.recv(result_len - len(result_data))
                        if not chunk:
                            break
                        result_data += chunk
                    server_result = json.loads(result_data.decode("utf-8"))
            except Exception:
                pass
            result = {
                "server_ip": server_ip,
                "port": port,
                "duration_s": round(total_elapsed, 3),
                "total_bytes": total_bytes,
                "total_MB": round(total_bytes / (1024 * 1024), 2),
                "client_speed_mbps": round(client_speed_mbps, 2),
                "client_speed_mbs": round(client_speed_mbs, 2),
            }
            if server_result:
                result["server_speed_mbps"] = server_result.get("speed_mbps", 0)
                result["server_speed_mbs"] = server_result.get("speed_mbs", 0)
            if progress_callback:
                progress_callback("Test completed", 1.0)
            self._log(f"Test completed: {client_speed_mbps:.2f} Mbps ({client_speed_mbs:.2f} MB/s)")
            return result
        except TimeoutError:
            self._log(f"Timeout: Could not connect to {server_ip}:{port}")
            return None
        except ConnectionRefusedError:
            self._log(f"Connection refused: Is the server running on {server_ip}:{port}?")
            return None
        except Exception as e:
            self._log(f"Error: {e}")
            return None
        finally:
            if sock:
                with contextlib.suppress(Exception):
                    sock.close()


def quick_latency_test(target_ip: str, count: int = 5) -> dict | None:
    """
    Quick TCP latency test against a host.
    Opens and closes connections to measure RTT.

    Args:
        target_ip: Destination IP
        count: Number of attempts

    Returns:
        Dictionary with min/avg/max/jitter in ms
    """
    if not is_private_ip(target_ip):
        return None

    latencies = []
    port = DEFAULT_PORT

    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        start = time.perf_counter()
        try:
            sock.connect((target_ip, port))
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
            sock.close()
        except Exception:
            sock.close()

    if not latencies:
        return None

    avg = sum(latencies) / len(latencies)
    jitter = max(latencies) - min(latencies) if len(latencies) > 1 else 0

    return {
        "min_ms": round(min(latencies), 2),
        "avg_ms": round(avg, 2),
        "max_ms": round(max(latencies), 2),
        "jitter_ms": round(jitter, 2),
        "samples": len(latencies),
    }
