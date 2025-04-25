#!/usr/bin/env python3
"""
Security Monitoring System with YAML Rule Engine

This script launches the security monitoring system with rules defined in a YAML configuration file.
"""

import os
import sys
import logging
import argparse
from Logger import Logger
from rule_engine import RuleEngine
from audit_log_monitor import AuditLogMonitor
from log_filter import process_event_sequence

def main():
    """Main entry point for the security monitoring system"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Security Monitoring System with Rule Engine')
    parser.add_argument('--log-file', dest='log_file', type=str, 
                        default='sample_auditd_logs/fork-test-c-program',
                        help='Path to the audit log file to monitor')
    parser.add_argument('--rules', dest='rules_file', type=str,
                        default='rules.yaml',
                        help='Path to the YAML rules configuration file')
    parser.add_argument('--log-level', dest='log_level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Logging level')
    parser.add_argument('--output', dest='output_file', type=str,
                        default='security_monitor.log',
                        help='Path to the output log file')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = getattr(logging, args.log_level)
    logger = Logger("security_monitor", args.output_file, log_level)
    
    # Initialize the rule engine
    rule_engine = RuleEngine(args.rules_file, logger)
    
    # Check if the log file exists
    if not os.path.exists(args.log_file):
        logger.error(f"Log file not found: {args.log_file}")
        return 1
    
    # Display startup information
    logger.info("Starting Security Monitoring System")
    logger.info(f"Monitoring log file: {args.log_file}")
    logger.info(f"Using rules from: {args.rules_file}")
    logger.info(f"Loaded {len(rule_engine.rules)} rules")
    
    # Initialize global variables in log_filter module
    import log_filter
    log_filter.rule_engine = rule_engine
    log_filter.logger = logger
    
    # Start the audit log monitor
    try:
        monitor = AuditLogMonitor(args.log_file, logger, rule_engine)
        logger.info("Monitoring started. Press Ctrl+C to exit.")
        monitor.monitor(process_event_sequence)
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user.")
    except Exception as e:
        logger.error(f"Error during monitoring: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 