import sys
from os import environ
from Process import Process
import logging

HOME_DIRECTORY = environ.get("HOME")
LOG_FILE_TO_MONITOR = "sample_auditd_logs/handful_logs"
PROTECTED_LOCATIONS = [f"{HOME_DIRECTORY}/safe-location"]
APP_LOG_FILE = "log_filter.log"

# List of locations (in addition to the protected locations) to which sensitive data may be moved
SAFE_LOCATIONS = [f"{HOME_DIRECTORY}/safe-location"]

process_map = dict()
logger = logging.getLogger("log_filter")


def split_logs_into_event_sequences(logs: str) -> [str]:
    """
    Splits raw event logs collected using auditd into individual events based on the delimiter "----".
    :param logs: A string which holds logs processed using ausearch
    :return: List of individual events.
    """
    return logs.split("----")


def is_path_sensitive(path: str) -> bool:
    """
    Determines if a path is sensitive by comparing it against each location prefix
    in PROTECTED_LOCATIONS. A path is considered sensitive if a location prefix matches
    (appears at the beginning) of the provided path.
    :param path: The path to be inspected
    :return: True if the path is sensitive, else False
    """
    for location_prefix in PROTECTED_LOCATIONS:
        if location_prefix in path:
            return True
    return False


def get_event_as_dict(log_event: str):
    """
    Transforms an event reported by ausearch into a dictonary, with each key-value pair
    representing one attribute-value pair from the event log.
    :param log_event: A string containing a single event log
    :return: The event from log_event as a dictionary
    """

    # The actual event data follows " : " in each event
    event = log_event.split(" : ")[1]
    event_dict = dict()

    # The event payload is composed of space separated attribute=value pairs
    for key_value_pair in event.split(" "):
        kv_pair = key_value_pair.strip()
        if len(kv_pair) == 0:
            continue
        key, value = kv_pair.split("=")
        event_dict[key] = value
    return event_dict


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
    paths = []
    sensitive_paths = []
    sensitive_path = False
    for event in events:
        if "PATH" in event:
            path_event_dict = get_event_as_dict(event)
            # The path in the PATH message is available as the value of the attribute "name"
            paths.append(path_event_dict['name'])
            if is_path_sensitive(event):
                sensitive_paths.append(path_event_dict['name'])
                sensitive_path = sensitive_path | True
        if "SYSCALL" in event:
            syscall = get_event_as_dict(event)
            if syscall['syscall'] == 'openat':
                if sensitive_path:
                    # Mark the process, its parent, and children sensitive
                    pid = syscall['pid']
                    ppid = syscall['ppid']

                    # Create a Process instance for this process, and its parent
                    create_process_if_not_exists(pid, ppid)
                    create_process_if_not_exists(ppid)

                    parent_process = process_map[ppid]
                    parent_process.add_child(pid)
                    # TODO : Think - should the path be prefixed with "Child"?
                    for path in sensitive_paths:
                        parent_process.add_sensitive_resource(path)
                    logger.info(f"The parent of process {pid} with PID {ppid} has been marked sensitive.")

                    process = process_map[pid]
                    process.ppid = ppid
                    for path in paths:
                        process.add_sensitive_resource(path)
                    process.propagate_sensitive_flag_to_children(process_map)
                    logger.info(f"The process {pid} and its children have been marked sensitive.")
                    logger.info(f"Sensitive paths: {paths}")
                else:
                    # If the process exists, and is sensitive
                    if (pid := syscall['pid']) in process_map:
                        process = process_map[pid]
                        if process.is_process_sensitive():
                            if 'O_WRONLY' in syscall['a2'] or 'O_RDWR' in syscall['a2']:
                                safe_write = True
                                for path in paths:
                                    safe_path = False
                                    for safe_loc_prefix in SAFE_LOCATIONS:
                                        if safe_loc_prefix in path:
                                            safe_path = safe_path | True
                                    safe_write = safe_write & safe_path
                                if not safe_write:
                                    logger.warning(
                                        f"The process with ID {pid} may write data to one or more unsafe locations. Write paths={paths}")


def main():
    # This configuration applies to loggers instantiated in all other modules. Calling basicConfig() in another
    # module will override this configuration.
    logging.basicConfig(level=logging.INFO, handlers=[logging.FileHandler(APP_LOG_FILE), logging.StreamHandler(sys.stdout)],
                        format="%(asctime)s - %(levelname)-8s - %(name)s - %(message)s")
    with open(LOG_FILE_TO_MONITOR, mode="r") as f_auditd_logs:
        logs = f_auditd_logs.read()
        events_sequences = split_logs_into_event_sequences(logs)
        for event_sequence in events_sequences:
            process_event_sequence(event_sequence)



if __name__ == "__main__":
    main()
