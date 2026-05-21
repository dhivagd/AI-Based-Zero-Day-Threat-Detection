"""
File system event monitoring module using watchdog.
Monitors file creation, modification, deletion, and other file operations.
"""
import asyncio
import logging
from typing import AsyncGenerator, Dict, Any, Optional, Set, Callable
from datetime import datetime
from pathlib import Path
import time

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("Watchdog not installed. File system monitoring will be limited.")


class ThreatDetectionEventHandler(FileSystemEventHandler):
    """Custom event handler that converts watchdog events to our format."""

    def __init__(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Initialize the event handler.

        Args:
            callback: Function to call when an event occurs.
        """
        super().__init__()
        self.callback = callback
        self.logger = logging.getLogger(__name__)

    def on_created(self, event):
        """Handle file/directory creation."""
        if not event.is_directory:
            self._handle_event(event, 'file_create')

    def on_modified(self, event):
        """Handle file/directory modification."""
        if not event.is_directory:
            self._handle_event(event, 'file_modify')

    def on_deleted(self, event):
        """Handle file/directory deletion."""
        if not event.is_directory:
            self._handle_event(event, 'file_delete')

    def on_moved(self, event):
        """Handle file/directory move/rename."""
        if not event.is_directory:
            self._handle_event(event, 'file_move', dest_path=event.dest_path)

    def _handle_event(self, event: FileSystemEvent, event_type: str, **kwargs):
        """Convert watchdog event to our internal format and call callback."""
        try:
            event_info = {
                'timestamp': datetime.fromtimestamp(time.time()),
                'event_type': event_type,
                'src_path': event.src_path,
                'is_directory': event.is_directory,
            }
            event_info.update(kwargs)

            # Add file size if it exists and is a file
            if not event.is_directory and Path(event.src_path).exists():
                try:
                    event_info['file_size'] = Path(event.src_path).stat().st_size
                except (OSError, FileNotFoundError):
                    event_info['file_size'] = 0

            self.callback(event_info)
        except Exception as e:
            self.logger.error(f"Error handling file system event: {e}")


class FileMonitor:
    """Monitors file system events using watchdog."""

    def __init__(self, paths_to_watch: list = None, recursive: bool = True):
        """
        Initialize file monitor.

        Args:
            paths_to_watch: List of directory paths to monitor. If None, monitors common sensitive directories.
            recursive: Whether to monitor subdirectories recursively.
        """
        self.logger = logging.getLogger(__name__)
        self._is_running = False
        self._observer = None
        self._event_queue = asyncio.Queue()
        self._paths_to_watch = paths_to_watch or self._get_default_paths()
        self._recursive = recursive

        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("Watchdog is required for file system monitoring. Install with: pip install watchdog")

    def _get_default_paths(self) -> list:
        """Get default paths to monitor based on OS."""
        import platform
        system = platform.system()
        paths = []

        if system == "Windows":
            paths = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
                "C:\\Windows\\Temp",
                "C:\\Users\\Public",
            ]
        elif system == "Linux" or system == "Darwin":
            paths = [
                "/tmp",
                "/var/tmp",
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
            ]
        else:
            paths = ["/tmp", os.path.expanduser("~/Downloads")]

        # Filter to only existing paths
        return [p for p in paths if os.path.exists(p)]

    async def start_monitoring(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously monitor file system events.

        Yields:
            Dict containing file system event information.
        """
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("Watchdog is not available.")

        self._is_running = True
        self.logger.info(f"Starting file system monitoring on paths: {self._paths_to_watch}")

        # Set up the observer and event handler
        event_handler = ThreatDetectionEventHandler(self._event_callback)
        self._observer = Observer()

        for path in self._paths_to_watch:
            if os.path.exists(path):
                self._observer.schedule(event_handler, path, recursive=self._recursive)
                self.logger.debug(f"Watching path: {path} (recursive: {self._recursive})")
            else:
                self.logger.warning(f"Path does not exist, skipping: {path}")

        self._observer.start()

        try:
            while self._is_running:
                try:
                    # Wait for event with timeout to allow checking self._is_running
                    event_info = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                    yield event_info
                except asyncio.TimeoutError:
                    continue
        except Exception as e:
            self.logger.error(f"Error in file monitoring loop: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the file system monitoring."""
        self._is_running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None
        self.logger.info("File system monitoring stopped.")

    def _event_callback(self, event_info: Dict[str, Any]):
        """Callback placed in the queue when a file system event occurs."""
        try:
            self._event_queue.put_nowait(event_info)
        except asyncio.QueueFull:
            self.logger.warning("File system event queue is full, dropping event")
        except Exception as e:
            self.logger.error(f"Error queuing file system event: {e}")


# Example usage (for testing)
if __name__ == "__main__":
    import asyncio
    import os

    async def test_monitoring():
        # Monitor current directory for testing
        monitor = FileMonitor(paths_to_watch=["."], recursive=False)
        count = 0
        async for event in monitor.start_monitoring():
            print(f"File event: {event}")
            count += 1
            if count >= 5:  # Just for demo
                break
        monitor.stop()

    # Uncomment to test (create/delete a file in current directory to see events)
    # asyncio.run(test_monitoring())