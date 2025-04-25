from Process import Process
from Logger import Logger
import logging

from audit_log_monitor import AuditLogMonitor
from utils import *

# List of path prefixes that define locations which store sensitive data. Each path in
# this list MUST be fully resolved (should not be relative).
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed", "/home/cs4440/safe-location"]
APP_LOG_FILE = "log_filter.log"


# List of locations (in addition to the protected locations) to which sensitive data may be moved.
# Each path in this list MUST be fully resolved (should not be relative).
SAFE_LOCATIONS = ["/home/cs4440/safe-location"]

# A dictionary that maps process IDs (string) to the corresponding `Process` object.
process_map = dict()

## Helper functions ##

def create_process_if_not_exists(pid, ppid=None, sensitive=False) -> bool:
    """
    Creates a process and adds it to the process map if it doesn't already exist
    :param pid: ID of the process to be created
    :return: True if a new Process instance was created, else False
    """
    if pid not in process_map:
        process_map[pid] = Process(pid, ppid, sensitive)
        return True
    return False

def is_path_read_sensitive(path: str) -> bool:
    """
    Determines if the supplied path is sensitive for a read operation. A path is
    considered read-sensitive if it begins with one of the prefixes provided in 
    `PROTECTED_LOCATION`.
    :param path: The path to be tested. The path MUST be fully resolved (should not be relative)
    :return: `True` if the path is read-sensitive, `False` otherwise.
    """
    return is_path_sensitive(path, PROTECTED_LOCATIONS)

def is_path_write_sensitive(path: str) -> bool:
    """
    Determines if the supplied path is sensitive for a write operation. A path is
    considered write-sensitive if it does not begin with any of the prefixes provided in 
    `SAFE_LOCATIONS`.
    :param path: The path to be tested. The path MUST be fully resolved (should not be relative)
    :return: `True` if the path is write-sensitive, `False` otherwise.
    """
    return (not is_path_sensitive(path, SAFE_LOCATIONS))

def add_read_sensitive_paths_to_process(process: Process, paths):
    """
    A convenience function that adds each path in :param:`paths` to the
    passed process' list of read-sensitive paths (if it isn't present already).
    :param paths: A list of read-sensitive paths.
    :return: Nothing
    """
    for path in paths: 
        process.add_sensitive_read_path(path)

def add_write_sensitive_paths_to_process(process: Process, paths):
    """
    A convenience function that adds each path in :param:`paths` to the
    passed process' list of write-sensitive paths (if it isn't present already).
    :param paths: A list of write-sensitive paths.
    :return: Nothing
    """
    for path in paths:
        process.add_sensitive_write_path(path)

## Helper functions end ##

def process_event_sequence(event_sequence: str):
    logger.debug(f"Current event sequence:\n{event_sequence}")
    events = event_sequence.split("\n")

    # List of all paths logged in this event
    paths = []
    
    # List of sensitive locations that might have been / may be read
    sensitive_read_paths = []

    # List of sensitive locations that might have been / may be written to
    sensitive_write_paths = []

    # The variables below will be used for reporting details in the event of a data exfiltration attempt
    sensitive_read = False
    sensitive_write = False
    sensitive_pid = None
    sensitive_pid_commands = []
    current_working_directory = None

    for event in events:
        if len(event.strip()) == 0:
            continue
        event_dict = get_event_as_dict(event)
        try:
            match event_dict['type']:
                # PROCTITLE logs the command associated with this event
                case 'PROCTITLE':
                    if 'proctitle' in event_dict:
                        sensitive_pid_commands.append(event[event.index('proctitle=')+10:])
                case 'PATH':
                    # The path in the PATH message is available as the value of the attribute "name"
                    path = event_dict['name']
                    mode = event_dict['nametype']
                    paths.append((path, mode))

                # The CWD message is logged after PATH messages. Resolve all recorded paths with respect to the
                # current working directory
                case 'CWD':
                    current_working_directory = event_dict['cwd']
                    paths = [(resolve_path_wrt_cwd(path, current_working_directory), mode) for path, mode in paths]

                    for path, mode in paths:
                        logger.debug(f"Inspecting path: {path}")
                        match mode:
                            case 'NORMAL':
                                if is_path_read_sensitive(path):
                                    sensitive_read = True
                                    sensitive_read_paths.append(path)
                                elif is_path_write_sensitive(path):
                                    sensitive_write = True
                                    sensitive_write_paths.append(path)
                            case 'CREATE':
                                if is_path_write_sensitive(path):
                                    sensitive_write = True
                                    sensitive_write_paths.append(path)
                            case 'TARGET':
                                if is_path_write_sensitive(path):
                                    sensitive_write = True
                                    sensitive_write_paths.append(path)
                            case 'DELETE':
                                if is_path_read_sensitive(path):
                                    sensitive_read = True
                                    sensitive_read_paths.append(path)
                            case 'SOURCE':
                                if is_path_read_sensitive(path):
                                    sensitive_read = True
                                    sensitive_read_paths.append(path)

                case 'EXECVE':
                    # An event of type EXECVE represents the event of a process loading a binary. The paths in such an
                    # event typically correspond to shared libaries and executables. We'll skip processing such logs at
                    # this stage since the paths record in this event will be treated as write sensitive (unless locations
                    # like /usr/bin/ are considered safe for writing)
                    return
                case 'SYSCALL':

                    pid = event_dict['pid']
                    ppid = event_dict['ppid']

                    # Create a Process instance for this process, and its parent
                    create_process_if_not_exists(pid, ppid)
                    create_process_if_not_exists(ppid)

                    parent_process = process_map[ppid]
                    parent_process.add_child(pid)

                    process = process_map[pid]
                    process.set_parent(ppid)

                    # Track cloning
                    match event_dict['syscall']:
                        case 'clone':
                            if event_dict['success'] == 'yes' and (child_pid := event_dict['exit']) != '0':
                                process.add_child(child_pid)
                                create_process_if_not_exists(child_pid)
                                child_process = process_map[child_pid]
                                child_process.set_parent(pid)
                                child_process.inherit_sensitivity_from_parent(pid, process_map)


                    # Update read sensitivity
                    if sensitive_read:
                        process.mark_process_read_sensitive()
                        add_read_sensitive_paths_to_process(process, sensitive_read_paths)
                        process.propagate_sensitive_flag_to_children(process_map)
                        sensitive_pid = pid

                    # Update write sensitivity
                    if sensitive_write:
                        process.mark_process_write_sensitive()
                        add_write_sensitive_paths_to_process(process, sensitive_write_paths)
                        process.propagate_sensitive_flag_to_children(process_map)
                        sensitive_pid = pid

                    sensitive_read = process.is_read_sensitive()
                    sensitive_write = process.is_write_sensitive()

                    sensitive_read_paths = process.get_sensitive_read_paths()
                    sensitive_write_paths = process.get_sensitive_write_paths()
        except Exception as e:
            logger.error(f"Error!\n{e}")     
    if sensitive_write and sensitive_read:
        logger.warning(
            f"The process with ID {sensitive_pid} may write data to one or more unsafe locations.\
            \nRead paths={sensitive_read_paths} \
            \nWrite paths={sensitive_write_paths}. \
            \nCurrent working directory={current_working_directory} \
            \nProcess command: {sensitive_pid_commands}")


# TODO - Only for testing. Delete later.
if __name__ == "__main__":
    logger = Logger("log_filter", "log_filter.log", logging.INFO)
    am = AuditLogMonitor("sample_auditd_logs/fork-test-c-program", logger)
    am.monitor(process_event_sequence)
