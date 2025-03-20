import fileinput
import auditdpythonparser
import Process, Syscall

LOG_FILE = "sample_auditd_logs/handful_logs"
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]

# List of locations (in addition to the protected locations) to which sensitive data may be moved
SAFE_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]

process_map = dict()

def split_logs_into_event_sequences(logs: str) -> [str]:
    # The default delimiter used by ausearch is "----"
    return logs.split("----")

def is_path_sensitive(path: str) -> bool:
    for location_prefix in PROTECTED_LOCATIONS:
        if location_prefix in path:
            return True
    return False

def get_event_as_dict(log_event: str):
    event = log_event.split(" : ")[1]
    event_dict = dict()

    for key_value_pair in event.split(" "):
        key, value = key_value_pair.split("=")
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
    events = event_sequence.split("\n")
    paths = []
    sensitive_path = False
    for event in events:
        if "PATH" in event:
            if is_path_sensitive(event):
                sensitive_path = sensitive_path | True
                path_event_dict = get_event_as_dict(event)
                paths.append(path_event_dict['name'])
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
                    map(parent_process.add_sensitive_resource, paths)

                    process = process_map[pid]
                    process.ppid = ppid
                    map(process.add_sensitive_resource, paths)
                    process.propagate_sensitive_flag_to_children(process_map)
                else:
                    # If the process exists, and is sensitive
                    if pid := syscall['pid'] in process_map:
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
                                    print(f"WARNING: The process with ID {pid} may write data to one or more unsafe locations. Write paths={paths}")








def main():
    with open(LOG_FILE, mode="r") as f_auditd_logs:
        logs = f_auditd_logs.read()
        events_sequences = split_logs_into_event_sequences(logs)
        for event_sequence in events_sequences:
            process_event_sequence(event_sequence)


if __name__ == "__main__":
    main()