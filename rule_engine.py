# rule_engine.py
"""
Rule Engine that loads human-readable rules from a YAML file and applies them
to each incoming audit event. Rules are defined in rules.yaml.
"""

import yaml
import logging

# Setup logging for the rule engine.
logging.basicConfig(
    filename="rule_engine.log",
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s:%(message)s"
)

# Global configuration for protected and safe locations.
PROTECTED_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]
SAFE_LOCATIONS = ["/home/cs4440/exfiltration-testbed"]

def is_path_sensitive(path: str) -> bool:
    """
    Check if a given path is within the protected locations.
    """
    for prefix in PROTECTED_LOCATIONS:
        if path.startswith(prefix):
            return True
    return False

def is_safe_path(path: str) -> bool:
    """
    Check if a given path is within safe locations.
    """
    for prefix in SAFE_LOCATIONS:
        if path.startswith(prefix):
            return True
    return False

class RuleEngine:
    def __init__(self, rules_file="rules.yaml"):
        """
        Initialize the Rule Engine and load rules from the YAML file.
        :param rules_file: Path to the rules YAML file.
        """
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        """
        Load rules from the YAML file.
        """
        try:
            with open(self.rules_file, "r") as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        except Exception as e:
            logging.error(f"Error loading rules: {e}")
            return []

    def evaluate_rule(self, rule, event, process_map):
        """
        Evaluate a rule's conditions against an event.
        :param rule: A rule dictionary.
        :param event: The event dictionary.
        :param process_map: Global process map for process tracking.
        :return: True if all conditions are met, else False.
        """
        context = {
            "event": event,
            "is_path_sensitive": is_path_sensitive,
            "is_safe_path": is_safe_path,
            "process_map": process_map
        }
        try:
            for condition in rule.get("conditions", []):
                if not eval(condition, {}, context):
                    return False
            return True
        except Exception as e:
            logging.error(f"Error evaluating rule '{rule.get('name', 'Unnamed')}': {e}")
            return False

    def apply_actions(self, rule, event, process_map):
        """
        Apply the actions specified by the rule.
        :param rule: The rule dictionary.
        :param event: The event dictionary.
        :param process_map: Global process map.
        """
        for action in rule.get("actions", []):
            if action == "mark_process_sensitive":
                self.mark_process_sensitive(event, process_map)
            elif action == "add_sensitive_resource":
                self.add_sensitive_resource(event, process_map)
            elif action == "alert_admin":
                self.alert_admin(rule, event)
            else:
                logging.warning(f"Unknown action: {action}")

    def mark_process_sensitive(self, event, process_map):
        """
        Mark a process (and its parent) as sensitive based on event data.
        """
        pid = event.get("pid")
        ppid = event.get("ppid")
        if pid and ppid:
            # Import Process here to avoid circular dependencies.
            from process import Process
            if pid not in process_map:
                process_map[pid] = Process(pid, ppid, sensitive=True)
            else:
                process_map[pid].sensitive = True
            if ppid not in process_map:
                process_map[ppid] = Process(ppid, None, sensitive=True)
            else:
                process_map[ppid].sensitive = True
            logging.info(f"Marked process {pid} and its parent {ppid} as sensitive.")

    def add_sensitive_resource(self, event, process_map):
        """
        Add a sensitive resource (path) to the process.
        """
        pid = event.get("pid")
        path = event.get("path", "")
        if pid:
            from process import Process
            if pid not in process_map:
                process_map[pid] = Process(pid)
            process_map[pid].add_sensitive_resource(path)
            logging.info(f"Added sensitive resource '{path}' to process {pid}.")

    def alert_admin(self, rule, event):
        """
        Alert the system administrator about a potential security issue.
        """
        message = rule.get("message", "Alert triggered.")
        logging.warning(f"ALERT: {message} | Event: {event}")
        # For demonstration, print the alert.
        print(f"ALERT: {message} | Event: {event}")

    def process_event(self, event, process_map):
        """
        Process a single event by iterating through all rules.
        :param event: Dictionary representing an event.
        :param process_map: Global process map.
        """
        for rule in self.rules:
            if rule.get("event_type", "") == event.get("type", ""):
                # If a specific syscall is defined, check for a match.
                if rule.get("syscall", "") and rule.get("syscall", "") != event.get("syscall", ""):
                    continue
                if self.evaluate_rule(rule, event, process_map):
                    self.apply_actions(rule, event, process_map)