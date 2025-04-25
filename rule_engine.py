import yaml
import os
import re
from Logger import Logger
import logging
from typing import Dict, List, Pattern, Any

class Rule:
    """
    Represents a single rule from the rules configuration.
    Each rule contains conditions and actions to be taken when conditions match.
    """
    def __init__(self, rule_id: str, name: str, description: str, conditions: Dict[str, Any], actions: List[str], severity: str = "INFO"):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.conditions = conditions
        self.actions = actions
        self.severity = severity
        self._compiled_patterns = {}
        
        # Precompile any regex patterns for better performance
        for key, value in conditions.items():
            if isinstance(value, str) and value.startswith("regex:"):
                pattern = value[6:].strip()  # Remove the 'regex:' prefix
                self._compiled_patterns[key] = re.compile(pattern)

    def matches(self, event_data: Dict[str, Any]) -> bool:
        """
        Check if the given event data matches this rule's conditions.
        """
        for key, condition in self.conditions.items():
            # Handle nested paths using dot notation (e.g., 'syscall.name')
            value = self._get_nested_value(event_data, key)
            
            if value is None:
                return False
                
            # Handle different condition types
            if key in self._compiled_patterns:
                # Regex matching
                if not self._compiled_patterns[key].search(str(value)):
                    return False
            elif isinstance(condition, list):
                # List matching (any value in list)
                if str(value) not in [str(c) for c in condition]:
                    return False
            elif isinstance(condition, str) and condition.startswith("!"):
                # Negated equality
                if str(value) == condition[1:]:
                    return False
            else:
                # Simple equality
                if str(value) != str(condition):
                    return False
                    
        return True
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract a value from a nested dictionary using dot notation.
        """
        parts = path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
                
        return current


class RuleEngine:
    """
    Rule engine that loads and evaluates YAML-based security rules.
    """
    def __init__(self, rules_file: str, logger: Logger):
        self.rules_file = rules_file
        self.logger = logger
        self.rules = []
        self.protected_locations = []
        self.safe_locations = []
        self.load_rules()
        
    def load_rules(self):
        """
        Load rules from the YAML configuration file.
        """
        try:
            if not os.path.exists(self.rules_file):
                self.logger.warning(f"Rules file {self.rules_file} does not exist. Creating default rules file.")
                self._create_default_rules_file()
                
            with open(self.rules_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # Load global configuration
            if 'global' in config:
                if 'protected_locations' in config['global']:
                    self.protected_locations = config['global']['protected_locations']
                if 'safe_locations' in config['global']:
                    self.safe_locations = config['global']['safe_locations']
            
            # Load individual rules
            if 'rules' in config:
                for rule_config in config['rules']:
                    rule = Rule(
                        rule_id=rule_config.get('id', f"rule_{len(self.rules)}"),
                        name=rule_config.get('name', 'Unnamed Rule'),
                        description=rule_config.get('description', ''),
                        conditions=rule_config.get('conditions', {}),
                        actions=rule_config.get('actions', []),
                        severity=rule_config.get('severity', 'INFO')
                    )
                    self.rules.append(rule)
                    
            self.logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to load rules: {e}")
            # Create default rules file if loading fails
            self._create_default_rules_file()
    
    def _create_default_rules_file(self):
        """
        Create a default rules file with sample rules.
        """
        default_config = {
            'global': {
                'protected_locations': ["/home/cs4440/exfiltration-testbed", "/home/cs4440/safe-location"],
                'safe_locations': ["/home/cs4440/safe-location"]
            },
            'rules': [
                {
                    'id': 'data_exfiltration',
                    'name': 'Data Exfiltration Detection',
                    'description': 'Detects when sensitive data is read and written to an unsafe location',
                    'conditions': {
                        'type': 'SYSCALL',
                        'syscall': ['write', 'pwrite', 'writev']
                    },
                    'actions': ['log_warning', 'track_process'],
                    'severity': 'WARNING'
                },
                {
                    'id': 'sensitive_file_access',
                    'name': 'Sensitive File Access',
                    'description': 'Detects access to sensitive files',
                    'conditions': {
                        'type': 'PATH',
                        'name': 'regex:.*\\.secret$'
                    },
                    'actions': ['log_info', 'track_process'],
                    'severity': 'INFO'
                }
            ]
        }
        
        try:
            with open(self.rules_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            self.logger.info(f"Created default rules file at {self.rules_file}")
            self.load_rules()  # Load the newly created rules
        except Exception as e:
            self.logger.error(f"Failed to create default rules file: {e}")
    
    def evaluate_event(self, event_data: Dict[str, Any]) -> List[Rule]:
        """
        Evaluate an event against all rules and return matching rules.
        """
        matched_rules = []
        
        for rule in self.rules:
            if rule.matches(event_data):
                matched_rules.append(rule)
                
        return matched_rules
    
    def execute_rule_actions(self, rule: Rule, event_data: Dict[str, Any], process_map: Dict[str, Any] = None):
        """
        Execute the actions defined in a rule.
        """
        for action in rule.actions:
            if action == 'log_info':
                self.logger.info(f"Rule '{rule.name}' triggered: {rule.description}")
            elif action == 'log_warning':
                self.logger.warning(f"Rule '{rule.name}' triggered: {rule.description} | Event: {event_data}")
            elif action == 'log_error':
                self.logger.error(f"Rule '{rule.name}' triggered: {rule.description} | Event: {event_data}")
            elif action == 'track_process' and process_map and 'pid' in event_data:
                # Mark the process for tracking (implementation depends on your Process class)
                pid = event_data.get('pid')
                if pid in process_map:
                    process = process_map[pid]
                    if 'mark_read_sensitive' in rule.actions:
                        process.mark_process_read_sensitive()
                    if 'mark_write_sensitive' in rule.actions:
                        process.mark_process_write_sensitive()
            # Additional actions can be implemented here
    
    def get_protected_locations(self) -> List[str]:
        """
        Return the list of protected locations from the rules configuration.
        """
        return self.protected_locations
    
    def get_safe_locations(self) -> List[str]:
        """
        Return the list of safe locations from the rules configuration.
        """
        return self.safe_locations 