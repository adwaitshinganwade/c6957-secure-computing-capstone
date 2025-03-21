# process.py
"""
Process class for managing process state and sensitive resource tracking.
This class is used by the rule engine to mark processes as sensitive and
to propagate sensitivity across parent-child relationships.
"""

from sys import stderr

class Process:
    def __init__(self, pid, ppid=None, sensitive=False):
        """
        Initialize a Process instance.
        :param pid: Process ID.
        :param ppid: Parent Process ID.
        :param sensitive: Flag indicating if the process is sensitive.
        """
        self.pid = pid
        self.ppid = ppid
        self.sensitive = sensitive
        self.children = []         # List of child process IDs.
        self.sensitive_paths = []  # List of sensitive resource paths.

    def add_child(self, child_pid):
        """Add a child process if not already present."""
        if child_pid not in self.children:
            self.children.append(child_pid)

    def remove_child(self, child_pid):
        """Remove a child process if it exists."""
        try:
            self.children.remove(child_pid)
        except ValueError:
            print(f"Process {self.pid} has no child with ID {child_pid}.", file=stderr)

    def add_sensitive_resource(self, sensitive_artifact_locator):
        """
        Add a sensitive resource locator (typically a file path) to the process.
        :param sensitive_artifact_locator: Path or identifier for the sensitive resource.
        """
        if sensitive_artifact_locator not in self.sensitive_paths:
            self.sensitive_paths.append(sensitive_artifact_locator)
        self.sensitive = True

    def remove_sensitive_resource(self, sensitive_artifact_locator):
        """
        Remove a sensitive resource locator from the process.
        """
        try:
            self.sensitive_paths.remove(sensitive_artifact_locator)
            if len(self.sensitive_paths) == 0:
                self.sensitive = False
        except ValueError:
            print(f"Resource {sensitive_artifact_locator} not found in process {self.pid}.", file=stderr)

    def is_process_sensitive(self) -> bool:
        """Return the current sensitivity status of the process."""
        return self.sensitive

    def propagate_sensitive_flag_to_children(self, process_map):
        """
        Recursively propagate the sensitive flag to all child processes.
        :param process_map: Dictionary mapping process IDs to Process instances.
        """
        if self.sensitive:
            for child_pid in self.children:
                try:
                    child = process_map[child_pid]
                    child.add_sensitive_resource("Parent:" + str(self.pid))
                    child.propagate_sensitive_flag_to_children(process_map)
                except KeyError:
                    print(f"Error: No child {child_pid} in process map while propagating from {self.pid}.", file=stderr)