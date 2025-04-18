from os import environ
from Process import Process
from Logger import Logger
import logging

from audit_log_monitor import AuditLogMonitor
from utils import *

HOME_DIR = environ.get("HOME")
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed", "/home/cs4440/safe-location"]
APP_LOG_FILE = "log_filter.log"


# List of locations (in addition to the protected locations) to which sensitive data may be moved
SAFE_LOCATIONS = ["/home/cs4440/safe-location"]

process_map = dict()


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
    return is_path_sensitive(path, PROTECTED_LOCATIONS)

def is_path_write_sensitive(path: str) -> bool:
    return (not is_path_sensitive(path, SAFE_LOCATIONS))

def process_event_sequence(event_sequence: str):
    logger.debug(f"Current event sequence:\n{event_sequence}")
    events = event_sequence.split("\n")

    # List of all paths logged in this event
    paths = []
    
    # List of paths that are not among those deemed safe for writing sensitive data
    unsafe_paths = []

    # List of paths that contain sensitive data
    sensitive_paths = []

    # The variables below will be used for reporting details in the event of a data exfiltration attempt
    sensitive_read = False
    sensitive_write = False
    sensitive_pid = None
    sensitive_pid_commands = []

    for event in events:
        if len(event.strip()) == 0:
            continue
        event_dict = get_event_as_dict(event)
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
                cwd = event_dict['cwd']
                paths = [(resolve_path_wrt_cwd(path, cwd), mode) for path, mode in paths]

                for path, mode in paths:
                    logger.debug(f"Inspecting path: {path}")
                    match mode:
                        case 'NORMAL':
                            if is_path_read_sensitive(path):
                                sensitive_read = True
                                sensitive_paths.append(path)
                            elif is_path_write_sensitive(path):
                                sensitive_write = True
                                unsafe_paths.append(path)
                        case 'CREATE':
                            if is_path_write_sensitive(path):
                                sensitive_write = True
                                unsafe_paths.append(path)
                        case 'TARGET':
                            if is_path_write_sensitive(path):
                                sensitive_write = True
                                unsafe_paths.append(path)
                        case 'DELETE':
                            if is_path_read_sensitive(path):
                                sensitive_read = True
                                sensitive_paths.append(path)
                        case 'SOURCE':
                            if is_path_read_sensitive(path):
                                sensitive_read = True
                                sensitive_paths.append(path)
            case 'SYSCALL':

                pid = event_dict['pid']
                ppid = event_dict['ppid']

                # Create a Process instance for this process, and its parent
                create_process_if_not_exists(pid, ppid)
                create_process_if_not_exists(ppid)

                parent_process = process_map[ppid]
                parent_process.add_child(pid)

                process = process_map[pid]
                process.ppid = ppid

                # Update read sensitivity
                if sensitive_read:
                    # TODO - propagate sensitivity to children
                    process.mark_process_read_sensitive()
                    process.propagate_sensitive_flag_to_children(process_map)
                    for path, _ in paths:
                        process.add_sensitive_resource(paths)

                # Update write sensitivity
                if sensitive_write:
                    process.mark_process_write_sensitive()
                    sensitive_pid = pid

                sensitive_read = process.is_read_sensitive()
                sensitive_write = process.is_write_sensitive()
                
    if sensitive_write and sensitive_read:
        logger.warning(
            f"The process with ID {sensitive_pid} may write data to one or more unsafe locations.\nWrite paths={unsafe_paths}.\nProcess command: {sensitive_pid_commands}")


# TODO - Only for testing. Delete later.
if __name__ == "__main__":
    logger = Logger("log_filter", "log_filter.log", logging.DEBUG)
    am = AuditLogMonitor("sample_auditd_logs/mv")
    am.monitor(process_event_sequence)
