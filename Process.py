import logging

APP_LOG_FILE = "log_filter.log"
logger = logging.getLogger(__name__)


class Process:
    """
    The :class:`Process` class represents a process, capturing meta-data of a process
    that is interesting from the perspective of monitoring activity that can
    lead to data exfiltration. The parent and children of each process can be recorded
    in an instance of `:class:`Process`. This helps build the tree associated with this
    process.
    
    Each instance of Process has the attributes :attr:`__sensitive_read`
    and :attr:`__sensitive_write` that indicate whether or not a process has read/written
    sensitive data. Additionally, this class provides convenience functions to propagate 
    sensitivity to/from a process and its parent/children.
    """
    def __init__(self, pid, ppid=None, sensitive=False):
        # ID of the process
        self.__pid = pid

        # ID of the process' parent
        self.__ppid = ppid

        # List of child processes
        self.__children = list()

        # Sensitive paths this process has access to (e.g., through open file handles)
        self.__sensitive_paths = list()

        # Sensitive read
        self.__sensitive_read = False

        # Sensitive read paths
        self.__sensitive_read_paths = list()

        # Sensitive write paths
        self.__sensitive_write_paths = list()

        # Sensitive write
        self.__sensitive_write = False

    def set_parent(self, parent_pid: str):
        """
        Sets the parent (PID) of this process.
        :param: parent_pid: The ID of the parent process
        :return: nothing
        """
        self.__ppid = parent_pid

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

    def mark_process_read_sensitive(self):
        """
        Marks a process as read sensitive.
        :return: nothing.
        """
        self.__sensitive_read = True

    def mark_process_write_sensitive(self):
        """
        Marks a process as write sensitive.
        :return: nothing.
        """
        self.__sensitive_write = True

    def is_read_sensitive(self) -> bool:
        """
        Retrieves the read sensitivity of this process.
        :return: `True` if the process is read sensitive, else `False`.
        """
        return self.__sensitive_read
    
    def is_write_sensitive(self) -> bool:
        """
        Retrieves the write sensitivity of this process.
        :return: `True` if the process is write sensitive, else `False`.
        """
        return self.__sensitive_write

    def __add_sensitive_resource(self, sensitive_resources, sensitive_artifact_locator: str):
        """
        Adds a locator for a sensitive artifact (typically a file) to :param:`sensitive_resources`.
        :param sensitive_resources: a list of sensitive resources (e.g., paths represented as strings).
        :param sensitive_artifact_locator: information useful for locating an artifact, typically a path
        :return: nothing
        """
        if sensitive_artifact_locator not in sensitive_resources:
            sensitive_resources.append(sensitive_artifact_locator)

    def __remove_sensitive_resource(self, sensitive_resources, sensitive_artifact_locator: str):
        """
        Removes a sensitive artifact from :param:`sensitive_resources`, indicating that this process can no longer access it.
        :param sensitive_resources: a list of sensitive resources (e.g., paths represented as strings).
        :param sensitive_artifact_locator:  identifier for the artifact to be removed. Should be the same as that used to add this artifact
        :return: nothing
        """
        try:
            sensitive_resources.remove(sensitive_artifact_locator)
        except ValueError:
            logger.error(f"Could not find {sensitive_artifact_locator} in the list of sensitive artifacts accessed by the process {self.__pid}")

    def add_sensitive_write_path(self, write_path: str):
        """
        Adds a sensitive path to this process' :attr:`self.__sensitive_write_paths`.
        :param write_path: The path to be added.
        """
        self.__add_sensitive_resource(self.__sensitive_write_paths, write_path)

    def add_sensitive_read_path(self, read_path: str):
        """
        Adds a sensitive path to this process' :attr:`self.__sensitive_read_paths`.
        :param read_path: The path to be added.
        """
        self.__add_sensitive_resource(self.__sensitive_read_paths, read_path)

    def remove_sensitive_write_path(self, write_path: str):
        """
        Removes a sensitive path from this process' :attr:`self.__sensitive_write_paths`.
        :param write_path: The path to be removed.
        """
        self.__remove_sensitive_resource(self.__sensitive_write_paths, write_path)

    def remove_sensitive_read_path(self, read_path: str):
        """
        Removes a sensitive path from this process' :attr:`self.__sensitive_read_paths`.
        :param read_path: The path to be removed.
        """
        self.__remove_sensitive_resource(self.__sensitive_read_paths, read_path)

    def get_sensitive_read_paths(self):
        return self.__sensitive_read_paths
    
    def get_sensitive_write_paths(self):
        return self.__sensitive_write_paths

    def inherit_sensitivity_from_parent(self, parent_pid, process_map):
        """
        Marks this process as read/write sensitive if its parent is 
        read/write sensitive. It is assumed that this function is used to
        "escalate" the sensitivity of a process if there is reason to believe
        that its parent might be performing sensitive I/O. That is, this 
        method is not intendend to mark the process as not sensitive based on
        its parent.
        :param parent_pid: The ID of this process' parent
        :process_map: The process tree
        :return: nothing
        """
        if parent_pid in process_map:
            parent = process_map[parent_pid]
            if parent.is_read_sensitive():
                self.mark_process_read_sensitive()
                self.__copy_sensitive_paths(parent, self)
            if parent.is_write_sensitive():
                self.mark_process_write_sensitive()
                self.__copy_sensitive_paths(parent, self, "w")

    def propagate_sensitive_flag_to_children(self, process_map):
        """
        If this process is sensitive, marks all of its children sensitive recursively. A child is marked
        sensitive by adding its parent's PID as a sensitive resource to its list of sensitive paths. This
        is done to indicate that the child inherits this status from its parent.
        :process_map: The process tree
        :return: Nothing
        """
        # To prevent this variable from remaining undefined due to short-circuting of the OR in the following condition
        write_sensitive = self.is_write_sensitive()
        if (read_sensitive := self.is_read_sensitive()) or write_sensitive:
            for child_pid in self.__children:
                try:
                    child = process_map[child_pid]
                    if read_sensitive:
                        child.mark_process_read_sensitive()
                        self.__copy_sensitive_paths(self, child)
                    if write_sensitive:
                        child.mark_process_write_sensitive()
                        self.__copy_sensitive_paths(self, child, "w")
                    child.propagate_sensitive_flag_to_children(process_map)
                except KeyError:
                    logger.error(f"Error while propagating sensitive status from {self.__pid} to child {child_pid}. No such child in the process map.")

    def __copy_sensitive_paths(self, src_process, dst_process, path_type="r"):
        """
        Copies the read/write sensitive paths from :param:`src_process` to 
        :param:`dst_process` based on :param:`path_type`.
        :param src_process: The process from which paths should be copied
        :param dst_process: The process to which paths should be copied
        :param path_type: "r" (default) for copying sensitive read paths. Sensitive write paths will be copied otherwise.
        """
        if path_type == "r":
            get_resource = src_process.get_sensitive_read_paths
            add_resource = dst_process.add_sensitive_read_path
        else:
            get_resource = src_process.get_sensitive_write_paths
            add_resource = dst_process.add_sensitive_write_path

        for path in get_resource():
            add_resource(path)
