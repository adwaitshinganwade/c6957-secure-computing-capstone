import logging

APP_LOG_FILE = "log_filter.log"
logger = logging.getLogger(__name__)


class Process:
    """
    The :class:`Process` class represents a process, capturing meta-data of a process
    that is interesting from the perspective of monitoring activity that can
    lead to data exfiltration. Each instance of Process has a :attr:`__sensitive`
    flag that is set to True when a process accessess sensitive data. 
    Additionally, this class provides a way to convenienty mark a process'
    parent and children sensitive as well.
    """
    def __init__(self, pid, ppid=None, sensitive=False):
        # ID of the process
        self.__pid = pid

        # ID of the process' parent
        self.__ppid = ppid

        # Flag that indicates whether or not the process is sensitive
        self.__sensitive = sensitive

        # List of child processes
        self.__children = list()

        # Sensitive paths this process has access to (e.g., through open file handles)
        self.__sensitive_paths = list()

    def add_child(self, child_pid: str):
        """
        Adds a process (PID) to the list of children of this process.
        <br> <b>NOTE</b>: The actual process instance is maintained in an external "process map."
        :param child_pid: The process ID of the child process
        :return:  nothing
        """
        if child_pid not in self.__children:
            self.__children.append(child_pid)

    def remove_child(self, child_pid: str):
        """
        Removes a process (PID) from the list of children of this process, if it exists.
        <br> <b>NOTE</b>: This will not delete the actual process instance of the child process.
        This operation indicates that is no longer a parent-child relationship between
        two processes.
        :param child_pid: The process ID of the child process
        :return: nothing
        """
        try:
            self.__children.remove(child_pid)
        except ValueError:
            logger.error(f"The process {self.__pid} has no child with ID {child_pid}.")

    def add_sensitive_resource(self, sensitive_artifact_locator: str):
        """
        Adds a locator for a sensitive artifact (typically a file) to :attr:`__sensitive_paths`.
        :param sensitive_artifact_locator: information useful for locating an artifact, typically a path
        :return: nothing
        """
        if sensitive_artifact_locator not in self.__sensitive_paths:
            self.__sensitive_paths.append(sensitive_artifact_locator)
        self.__sensitive = True

    def remove_sensitive_resource(self, sensitive_artifact_locator: str):
        """
        Removes a sensitive artifact from :attr:`__sensitive_paths`, indicating that this process can no longer access it.
        :param sensitive_artifact_locator:  identifier for the artifact to be removed. Should be the same as that used to add this artifact
        :return: nothing
        """
        try:
            self.__sensitive_paths.remove(sensitive_artifact_locator)
            if len(self.__sensitive_paths) == 0:
                self.__sensitive = False
        except ValueError:
            logger.error(f"Could not find {sensitive_artifact_locator} in the list of sensitive artifacts accessed by the process {self.__pid}")

    def is_process_sensitive(self) -> bool:
        """
        Relays this process' current level of sensitivity.
        :return: `True` if the process is sensitive, else `False`.    
        """
        return self.__sensitive

    def propagate_sensitive_flag_to_children(self, process_map):
        """
        If this process is sensitive, marks all of its children sensitive recursively. A child is marked
        sensitive by adding its parent's PID as a sensitive resource to its list of sensitive paths. This
        is done to indicate that the child inherits this status from its parent.
        :return: Nothing
        """
        if self.__sensitive:
            for child_pid in self.__children:
                try:
                    child = process_map[child_pid]
                    child.add_sensitive_resource("Parent:"+self.__pid)
                    child.propagate_sensitive_flag_to_children(process_map)
                except KeyError:
                    logger.error(f"Error while propagating sensitive status from {self.__pid} to child {child_pid}. No such child in the process map.")

