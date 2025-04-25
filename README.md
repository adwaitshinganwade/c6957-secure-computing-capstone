# Security Audit Log Monitoring System with Rule Engine

This system monitors audit logs to detect potential security threats, with a focus on data exfiltration detection. It has been enhanced with a YAML-based rule engine that allows for easy configuration of security rules without modifying code.

## Features

- Monitors audit logs in real-time
- Detects sensitive file operations
- Tracks process lineage to follow data access patterns
- Rule-based detection system using YAML configuration
- Flexible and customizable without code changes

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Configure your rules in `rules.yaml`

3. Run the log filter:

```bash
python log_filter.py
```

## Rule Engine

The rule engine allows you to define security rules in a YAML file without modifying code. This makes it easy for non-technical users to add new rules or modify existing ones.

### Rule Configuration (rules.yaml)

The rules are defined in `rules.yaml` with the following structure:

```yaml
global:
  # Locations containing sensitive data
  protected_locations:
    - "/home/cs4440/exfiltration-testbed"
    - "/home/cs4440/safe-location"
  
  # Locations where it's safe to write sensitive data
  safe_locations:
    - "/home/cs4440/safe-location"

rules:
  - id: unique_rule_id
    name: "Human-readable Rule Name"
    description: "Detailed description of what this rule detects"
    severity: WARNING  # Can be INFO, WARNING, or ERROR
    conditions:
      # Conditions to match against events
      type: PATH
      name: "regex:.*\\.secret$"
    actions:
      # Actions to take when conditions match
      - log_warning
      - track_process
```

### Defining Rules

Rules consist of the following components:

1. **id**: A unique identifier for the rule
2. **name**: A human-readable name
3. **description**: A description of what the rule detects
4. **severity**: The severity level (INFO, WARNING, ERROR)
5. **conditions**: Criteria that must be met for the rule to trigger
6. **actions**: Actions to take when the rule is triggered

### Conditions

Conditions define when a rule should trigger. You can use various types of conditions:

- **Simple Matching**: `key: value` matches exactly
- **List Matching**: `key: [value1, value2]` matches if the field equals any value in the list
- **Regex Matching**: `key: "regex:pattern"` matches if the field matches the regex pattern
- **Negated Matching**: `key: "!value"` matches if the field does NOT equal the value

### Available Actions

The following actions can be triggered when a rule matches:

- **log_info**: Log the event at INFO level
- **log_warning**: Log the event at WARNING level
- **log_error**: Log the event at ERROR level
- **track_process**: Track the process in the process map
- **mark_read_sensitive**: Mark the process as having read sensitive data
- **mark_write_sensitive**: Mark the process as potentially writing sensitive data

### Example Rules

Here are some example rules:

#### Detect File Exfiltration
```yaml
- id: data_exfiltration
  name: "Data Exfiltration Detection"
  description: "Detects when sensitive data is read and written to an unsafe location"
  severity: WARNING
  conditions:
    type: SYSCALL
    syscall: 
      - write
      - pwrite
      - writev
  actions:
    - log_warning
    - track_process
    - mark_write_sensitive
```

#### Detect Password File Access
```yaml
- id: credential_access
  name: "Password File Access"
  description: "Detects access to password or credential files"
  severity: WARNING
  conditions:
    type: PATH
    name: "regex:.*passwd|.*shadow|.*credentials.*"
  actions:
    - log_warning
    - track_process
    - mark_read_sensitive
```

## Adding New Rules

To add a new rule:

1. Open `rules.yaml` in a text editor
2. Add a new rule entry following the format above
3. Save the file
4. Restart the log filter if it's already running

No code changes are needed to add or modify rules!

## Components

- **log_filter.py**: Main application that monitors audit logs and applies rules
- **rule_engine.py**: Rule engine implementation
- **rules.yaml**: YAML file containing security rules
- **audit_log_monitor.py**: Monitors audit log files for new events
- **Process.py**: Represents a process and tracks its state
- **Logger.py**: Logging utility
- **utils.py**: Utility functions for path handling and event parsing