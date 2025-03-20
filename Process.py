from sys import stderr


class Process:
    def __init__(self, pid, ppid=None, sensitive=False):
        # ID of the process
        self.pid = pid

        # ID of the process' parent
        self.ppid = ppid

        # Flag that indicates whether or not the process is sensitive
        self.sensitive = sensitive

        # List of child processes
        self.children = list()

        # Sensitive paths this process has access to (e.g., through open file handles)
        self.sensitive_paths = list()

    def add_child(self, child_pid):
        if child_pid not in self.children:
            self.children.append(child_pid)

    def remove_child(self, child_pid):
        try:
            self.children.remove(child_pid)
        except ValueError:
            print(f"The process {self.pid} has no child with ID {child_pid}.", file=stderr)

    def add_sensitive_resource(self, sensitive_artifact_locator):
        """
        Adds a locator for a sensitive artifact (typically a file) to self.sensitive_paths.
        :param sensitive_artifact_locator: information useful for locating an artifact, typically a path
        :return: nothing
        """
        if sensitive_artifact_locator not in self.sensitive_paths:
            self.sensitive_paths.append(sensitive_artifact_locator)
        self.sensitive = True

    def remove_sensitive_resource(self, sensitive_artifact_locator):
        """
        Removes a sensitive artifact from self.sensitive_paths, indicating that this process can no longer access it.
        :param sensitive_artifact_locator:  identifier for the artifact to be removed. Should be the same as that used to add this artifact
        :return: nothing
        """
        try:
            self.sensitive_paths.remove(sensitive_artifact_locator)
        except ValueError:
            print(f"Could not find {sensitive_artifact_locator} in the list of sensitive artifacts accessed by the process {self.pid}", file=stderr)

    def is_process_sensitive(self) -> bool:
        return (len(self.sensitive_paths) >=1)

    def propagate_sensitive_flag_to_children(self, process_map):
        """
        If this process is sensitive, marks all of its children sensitive recursively. A child is marked
        sensitive by adding its parent's PID as a sensitive resource to its list of sensitive paths. This
        is done to indicate that the child inherits this status from its parent.
        :return: Nothing
        """
        if self.sensitive:
            for child_pid in self.children:
                try:
                    child = process_map[child_pid]
                    child.add_sensitive_resource("Parent:"+self.pid)
                    child.propagate_sensitive_flag_to_children(process_map)
                except KeyError:
                    print(f"Error while propagating sensitive status from {self.pid} to child {child_pid}. No such child in the process map.", file=stderr)

