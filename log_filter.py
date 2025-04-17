from os import environ
from Process import Process
from Logger import Logger
import logging

from audit_log_monitor import AuditLogMonitor
from utils import *

HOME_DIR = environ.get("HOME")
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]
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

def process_event_sequence(event_sequence: str):
    logger.debug(f"Current event sequence:\n{event_sequence}")
    events = event_sequence.split("\n")
    # TODO - make sure that paths are normalized w.r.t. the CWD
    paths = []
    sensitive_paths = []
    sensitive_path = False
    sensitive_read = False
    sensitive_write = False

    for event in events:
        if len(event.strip()) == 0:
            continue
        event_dict = get_event_as_dict(event)
        match event_dict['type']:
            case 'PATH':
                # The path in the PATH message is available as the value of the attribute "name"
                path = event_dict['name']
                paths.append(path)
                logger.debug(f"Inspecting path: {path}")
                if is_path_sensitive(path, PROTECTED_LOCATIONS):
                    logger.debug(f"This path looks sensitive: {path}")
                    sensitive_paths.append(path)
                    sensitive_path = sensitive_path | True
                    sensitive_read = True



            case 'SYSCALL':
                # Mark the process, its parent, and children sensitive
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
                    process.mark_process_read_sensitive()

                if event_dict['syscall'] == 'openat':
                    # TODO : Think - should the path be prefixed with "Child"?
                    for path in sensitive_paths:
                        parent_process.add_sensitive_resource(path)
                        process.add_sensitive_resource(path)
                    # logger.info(f"The parent of process {pid} with PID {ppid} has been marked sensitive.")

                    process.propagate_sensitive_flag_to_children(process_map)
                    # logger.info(f"The process {pid} read from a sensitive path. {pid} and its children have been marked sensitive.\nProcess command: {event_dict['comm']}\nSensitive paths: {sensitive_paths}")

                    if 'O_WRONLY' in event_dict['a2'] or 'O_RDWR' in event_dict['a2']:
                        # Look for writes to sensitive locations
                        for path in paths:
                            if not is_path_sensitive(path, SAFE_LOCATIONS):
                                sensitive_write = True
                                process.mark_process_write_sensitive()
                                logger.info(f"The process {pid} may write to an unsafe location. Location: {path}")
                            # safe_write = True
                            # for path in paths:
                            #     safe_path = False
                            #     for safe_loc_prefix in SAFE_LOCATIONS:
                            #         if path.startswith(safe_loc_prefix):
                            #             safe_path = safe_path | True
                            #     safe_write = safe_write & safe_path
                            # if not safe_write:
                                logger.warning(
                                    f"The process with ID {pid} may write data to one or more unsafe locations.\nWrite paths={paths}.\nProcess command: {event_dict['comm']}")
                logger.debug(f"Sensitive read: {process.is_read_sensitive()}.\nSensitive write: {process.is_write_sensitive()}")
                sensitive_read = process.is_read_sensitive()
                sensitive_write = process.is_write_sensitive() 
       
    if  sensitive_write and sensitive_read:
        logger.warning(f"SOMETHING FISHY!")



# TODO - Only for testing. Delete later.
if __name__ == "__main__":
    logger = Logger("log_filter", "log_filter.log", logging.DEBUG)
    am = AuditLogMonitor("sample_auditd_logs/handful_logs")
    am.monitor(process_event_sequence)