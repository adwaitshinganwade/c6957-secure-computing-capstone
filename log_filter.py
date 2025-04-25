from Process import Process
from Logger import Logger
import logging

from audit_log_monitor import AuditLogMonitor
from utils import *
from rule_engine import RuleEngine

# Default log file
APP_LOG_FILE = "log_filter.log"
RULES_FILE = "rules.yaml"

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

def is_path_read_sensitive(path: str, rule_engine) -> bool:
    """
    Determines if the supplied path is sensitive for a read operation using the rule engine.
    """
    return is_path_sensitive(path, rule_engine.get_protected_locations())

def is_path_write_sensitive(path: str, rule_engine) -> bool:
    """
    Determines if the supplied path is sensitive for a write operation using the rule engine.
    """
    return (not is_path_sensitive(path, rule_engine.get_safe_locations()))

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
    global logger, rule_engine
    
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

    # Convert event sequence to an event_data dictionary for rule processing
    event_data = {
        'events': [],
        'paths': [],
        'sensitive_read_paths': [],
        'sensitive_write_paths': [],
        'pid': None,
        'ppid': None,
        'syscall': None,
        'success': None,
        'type': None,
        'executable': None,
        'cwd': None
    }

    for event in events:
        if len(event.strip()) == 0:
            continue
        event_dict = get_event_as_dict(event)
        
        # Add this event to the event_data for rule processing
        event_data['events'].append(event_dict)
        
        # Update specific fields in event_data for easier rule matching
        if 'type' in event_dict:
            event_data['type'] = event_dict['type']
        if 'pid' in event_dict:
            event_data['pid'] = event_dict['pid']
        if 'ppid' in event_dict:
            event_data['ppid'] = event_dict['ppid']
        if 'syscall' in event_dict:
            event_data['syscall'] = event_dict['syscall']
        if 'success' in event_dict:
            event_data['success'] = event_dict['success']
        
        try:
            match event_dict['type']:
                # PROCTITLE logs the command associated with this event
                case 'PROCTITLE':
                    if 'proctitle' in event_dict:
                        proctitle = event[event.index('proctitle=')+10:]
                        sensitive_pid_commands.append(proctitle)
                        event_data['executable'] = proctitle
                case 'PATH':
                    # The path in the PATH message is available as the value of the attribute "name"
                    path = event_dict['name']
                    mode = event_dict['nametype']
                    paths.append((path, mode))
                    event_data['paths'].append(path)

                # The CWD message is logged after PATH messages. Resolve all recorded paths with respect to the
                # current working directory
                case 'CWD':
                    current_working_directory = event_dict['cwd']
                    event_data['cwd'] = current_working_directory
                    resolved_paths = []
                    
                    for path, mode in paths:
                        resolved_path = resolve_path_wrt_cwd(path, current_working_directory)
                        resolved_paths.append((resolved_path, mode))
                        
                        logger.debug(f"Inspecting path: {resolved_path}")
                        match mode:
                            case 'NORMAL':
                                if is_path_read_sensitive(resolved_path, rule_engine):
                                    sensitive_read = True
                                    sensitive_read_paths.append(resolved_path)
                                    event_data['sensitive_read_paths'].append(resolved_path)
                                elif is_path_write_sensitive(resolved_path, rule_engine):
                                    sensitive_write = True
                                    sensitive_write_paths.append(resolved_path)
                                    event_data['sensitive_write_paths'].append(resolved_path)
                            case 'CREATE':
                                if is_path_write_sensitive(resolved_path, rule_engine):
                                    sensitive_write = True
                                    sensitive_write_paths.append(resolved_path)
                                    event_data['sensitive_write_paths'].append(resolved_path)
                            case 'TARGET':
                                if is_path_write_sensitive(resolved_path, rule_engine):
                                    sensitive_write = True
                                    sensitive_write_paths.append(resolved_path)
                                    event_data['sensitive_write_paths'].append(resolved_path)
                            case 'DELETE':
                                if is_path_read_sensitive(resolved_path, rule_engine):
                                    sensitive_read = True
                                    sensitive_read_paths.append(resolved_path)
                                    event_data['sensitive_read_paths'].append(resolved_path)
                            case 'SOURCE':
                                if is_path_read_sensitive(resolved_path, rule_engine):
                                    sensitive_read = True
                                    sensitive_read_paths.append(resolved_path)
                                    event_data['sensitive_read_paths'].append(resolved_path)
                                    
                    # Update paths with resolved paths
                    paths = resolved_paths

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

                    # Process rule matching for this event
                    matching_rules = rule_engine.evaluate_event(event_data)
                    for rule in matching_rules:
                        rule_engine.execute_rule_actions(rule, event_data, process_map)

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
            
    # Log potential data exfiltration (this is kept from the original implementation)
    if sensitive_write and sensitive_read:
        logger.warning(
            f"The process with ID {sensitive_pid} may write data to one or more unsafe locations.\
            \nRead paths={sensitive_read_paths} \
            \nWrite paths={sensitive_write_paths}. \
            \nCurrent working directory={current_working_directory} \
            \nProcess command: {sensitive_pid_commands}")


# Entry point for the program
def main():
    global logger, rule_engine
    
    # Initialize the logger
    logger = Logger("log_filter", APP_LOG_FILE, logging.INFO)
    logger.info("Initializing log filter with rule engine...")
    
    # Initialize the rule engine
    rule_engine = RuleEngine(RULES_FILE, logger)
    
    # Get the audit log file from environment or use default
    audit_log_file = "sample_auditd_logs/fork-test-c-program"  # Default for testing
    
    logger.info(f"Starting audit log monitor on {audit_log_file}")
    am = AuditLogMonitor(audit_log_file, logger)
    am.monitor(process_event_sequence)


# Entry point when run directly
if __name__ == "__main__":
    main()
