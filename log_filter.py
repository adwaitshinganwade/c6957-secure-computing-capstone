import fileinput
import auditdpythonparser

LOG_FILE = "sample_auditd_logs/audit.log"


# for line in fileinput.input(LOG_FILE, encoding='UTF-8'):
#     print(line)
#     print("-x-x-x-x-x-x-x-x-x-x-")

with open(LOG_FILE, mode="r") as f_auditd_logs:
    logs = f_auditd_logs.read()
    auditd_logs = auditdpythonparser.parsedata(logs)
