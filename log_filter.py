import fileinput
import auditdpythonparser
import Process, Syscall

LOG_FILE = "sample_auditd_logs/handful_logs"
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]

# List of locations (in addition to the protected locations) to which sensitive data may be moved
SAFE_LOCATIONS = []

process_map = dict()

def split_logs_into_event_sequences(logs: str) -> [str]:
    # The default delimiter used by ausearch is "----"
    return logs.split("----")

def is_path_sensitive(path: str) -> bool:
    for location_prefix in PROTECTED_LOCATIONS:
        if location_prefix in path:
            return True
    return False

def get_syscall_as_dict(syscall_event: str):
    syscall = syscall_event.split(" : ")[1]
    syscall_dict = dict()

    for key_value_pair in syscall.split(" "):
        key, value = key_value_pair.split("=")
        syscall_dict[key] = value
    return syscall_dict
def process_event_sequence(event_sequence: str):
    events = event_sequence.split("\n")
    paths = []
    sensitive_path = False
    for event in events:
        if "PATH" in event:
            if is_path_sensitive(event):
                sensitive_path = True
                # TODO - Add path to paths
            print(f"This event accesses a sensitive location: {sensitive_path}")
        if "SYSCALL" in event:
            syscall = get_syscall_as_dict(event)
            if syscall['syscall'] == 'openat':
                # Outer if-else for READ and WRITE syscalls
                if sensitive_path and "O_RDONLY" in syscall[2]:
                    if pid := syscall['pid'] not in process_map:
                        process_map[pid] = Process(pid, syscall['ppid'], sensitive_path)
                    else:
                        process_map[pid].add_sensitive_resource()
                elif "O_WRONLY" in syscall[2] or "O_RDWR" in syscall[2]:
                    if  syscall['pid'] in process_map and process_map[syscall['pid']].is_process_sensitive():
                        safe_write = False
                        # TODO - If any of the paths in this event are not among safe paths, this is an unsafe write





def main():
    with open(LOG_FILE, mode="r") as f_auditd_logs:
        logs = f_auditd_logs.read()
        events_sequences = split_logs_into_event_sequences(logs)
        for event_sequence in events_sequences:
            process_event_sequence(event_sequence)


if __name__ == "__main__":
    main()