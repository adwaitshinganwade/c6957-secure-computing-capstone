# audit_log_monitor.py
"""
AuditLogMonitor continuously tails the audit log file and delivers complete event sequences
to the registered callback for further processing.
"""

import time
import os

class AuditLogMonitor:
    def __init__(self, log_file, delimiter="----"):
        """
        Initialize the audit log monitor.
        :param log_file: Path to the audit log file.
        :param delimiter: String delimiter that separates event sequences.
        """
        self.log_file = log_file
        self.delimiter = delimiter

    def follow(self):
        """
        Generator that yields new lines appended to the log file.
        """
        with open(self.log_file, "r") as file:
            file.seek(0, os.SEEK_END)  # Move to end of file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)  # No new data; wait and retry.
                    continue
                yield line

    def monitor(self, callback):
        """
        Monitor the log file and call the callback with each complete event sequence.
        :param callback: Function to process an event sequence.
        """
        buffer = ""
        for line in self.follow():
            buffer += line
            if self.delimiter in buffer:
                # Split into complete event sequences and an incomplete remainder.
                events = buffer.split(self.delimiter)
                buffer = events.pop()  # Incomplete part remains in the buffer.
                for event_sequence in events:
                    if event_sequence.strip():
                        callback(event_sequence.strip())