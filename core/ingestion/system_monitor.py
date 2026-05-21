"""
System call and process monitoring module.
Supports Linux (/proc filesystem) and Windows (ETW) platforms.
"""
import asyncio
import logging
import os
import platform
import psutil
from typing import AsyncGenerator, Dict, Any, Optional, List
from datetime import datetime
import subprocess
import json

logger = logging.getLogger(__name__)

# Platform detection
IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"


class SystemMonitor:
    """Monitors system calls, process creation, and other system activities."""

    def __init__(self, poll_interval: float = 0.1):
        """
        Initialize system monitor.

        Args:
            poll_interval: Time between checks in seconds.
        """
        self.poll_interval = poll_interval
        self.logger = logging.getLogger(__name__)
        self._is_running = False
        self._last_processes = {}
        self._last_network_connections = set()

        if not (IS_LINUX or IS_WINDOWS):
            self.logger.warning(f"System monitoring on {platform.system()} may have limited functionality.")

    async def start_monitoring(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously monitor system activities.

        Yields:
            Dict containing system event information.
        """
        self._is_running = True
        self.logger.info(f"Starting system monitoring on {platform.system()}")

        # Initialize baseline
        await self._get_baseline()

        try:
            while self._is_running:
                # Collect various system events
                events = []

                # Process creation/termination
                proc_events = await self._monitor_processes()
                events.extend(proc_events)

                # Network connections
                net_events = await self._monitor_network()
                events.extend(net_events)

                # System call monitoring (Linux specific)
                if IS_LINUX:
                    syscall_events = await self._monitor_system_calls()
                    events.extend(syscall_events)

                # File system events (using watchdog would be better, but basic polling for now)
                fs_events = await self._monitor_file_system()
                events.extend(fs_events)

                # Yield all events
                for event in events:
                    yield event

                # Wait before next poll
                await asyncio.sleep(self.poll_interval)

        except Exception as e:
            self.logger.error(f"Error in system monitoring: {e}")
        finally:
            self._is_running = False

    def stop(self):
        """Stop the system monitoring."""
        self._is_running = False
        self.logger.info("System monitoring stopped.")

    async def _get_baseline(self):
        """Get initial baseline of processes and network connections."""
        self._last_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time'])}
        self._last_network_connections = set(self._get_network_connections())

    async def _monitor_processes(self) -> List[Dict[str, Any]]:
        """Monitor for process creation and termination."""
        events = []
        try:
            current_processes = {}
            current_time = datetime.now()

            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    current_processes[pid] = proc_info

                    # Check if this is a new process
                    if pid not in self._last_processes:
                        events.append({
                            'timestamp': current_time,
                            'event_type': 'process_create',
                            'pid': pid,
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'username': proc_info['username'],
                            'parent_pid': self._get_parent_pid(proc),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Check for terminated processes
            for pid, proc_info in self._last_processes.items():
                if pid not in current_processes:
                    events.append({
                        'timestamp': datetime.now(),
                        'event_type': 'process_terminate',
                        'pid': pid,
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                    })

            self._last_processes = current_processes

        except Exception as e:
            self.logger.debug(f"Error monitoring processes: {e}")

        return events

    def _get_parent_pid(self, proc) -> Optional[int]:
        """Get parent PID of a process."""
        try:
            return proc.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    async def _monitor_network(self) -> List[Dict[str, Any]]:
        """Monitor for new network connections."""
        events = []
        try:
            current_connections = set(self._get_network_connections())
            new_connections = current_connections - self._last_network_connections
            terminated_connections = self._last_network_connections - current_connections

            current_time = datetime.now()

            for conn in new_connections:
                events.append({
                    'timestamp': current_time,
                    'event_type': 'network_connect',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'family': str(conn.family),
                    'type': str(conn.type),
                })

            for conn in terminated_connections:
                events.append({
                    'timestamp': current_time,
                    'event_type': 'network_disconnect',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'pid': conn.pid,
                })

            self._last_network_connections = current_connections

        except Exception as e:
            self.logger.debug(f"Error monitoring network: {e}")

        return events

    def _get_network_connections(self) -> List:
        """Get current network connections."""
        try:
            return psutil.net_connections(kind='inet')  # IPv4 and IPv6
        except Exception:
            return []

    async def _monitor_system_calls(self) -> List[Dict[str, Any]]:
        """
        Monitor system calls (Linux-specific using ptrace or similar would be complex).
        For now, we'll use indirect monitoring via process behavior.
        A full implementation would require kernel modules or eBPF.
        """
        events = []
        # This is a placeholder - real syscall monitoring would be more complex
        # For now, we monitor specific suspicious behaviors indirectly
        try:
            # Look for processes making many open/close syscalls (file churn)
            # Or processes making unusual network syscalls
            # This would require more sophisticated implementation
            pass
        except Exception as e:
            self.logger.debug(f"Error monitoring system calls: {e}")
        return events

    async def _monitor_file_system(self) -> List[Dict[str, Any]]:
        """Monitor file system events (basic polling approach)."""
        events = []
        # This would be better served by the watchdog module in ingestion/
        # For now, we'll monitor for suspicious file operations via process monitoring
        try:
            # Look for processes accessing sensitive files
            sensitive_paths = ['/etc/passwd', '/etc/shadow', '/root/', '/home/*/.ssh/', 'C:\\Windows\\System32\\']
            current_time = datetime.now()

            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for file_info in proc.info['open_files']:
                            file_path = file_info.path
                            # Check if accessing sensitive paths
                            for sens_path in sensitive_paths:
                                if '*' in sens_path:
                                    # Simple wildcard check
                                    import fnmatch
                                    if fnmatch.fnmatch(file_path, sens_path):
                                        events.append({
                                            'timestamp': current_time,
                                            'event_type': 'sensitive_file_access',
                                            'pid': proc.info['pid'],
                                            'name': proc.info['name'],
                                            'file_path': file_path,
                                            'access_type': 'read',  # We don't distinguish read/write from open_files
                                        })
                                elif sens_path in file_path:
                                    events.append({
                                        'timestamp': current_time,
                                        'event_type': 'sensitive_file_access',
                                        'pid': proc.info['pid'],
                                        'name': proc.info['name'],
                                        'file_path': file_path,
                                        'access_type': 'read',
                                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.debug(f"Error monitoring file system: {e}")

        return events


# Windows-specific ETW monitoring would go here if we had the pywin32 extensions
if IS_WINDOWS:
    try:
        import win32evtlog
        import win32con
        import win32api
        WINDOWS_ETW_AVAILABLE = True
    except ImportError:
        WINDOWS_ETW_AVAILABLE = False
        logger.warning("Windows ETW monitoring requires pywin32. Install with: pip install pywin32")


# Example usage (for testing)
if __name__ == "__main__":
    import asyncio

    async def test_monitoring():
        monitor = SystemMonitor(poll_interval=1.0)
        count = 0
        async for event in monitor.start_monitoring():
            print(f"Event: {event}")
            count += 1
            if count >= 5:  # Just for demo
                break
        monitor.stop()

    # Uncomment to test
    # asyncio.run(test_monitoring())