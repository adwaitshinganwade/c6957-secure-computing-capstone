from os.path import join

# Sensitive directory
RESTRICTED_DIR = "/home/cs4440/safe-location"
RESTRICTED_FILE = "secret"

# Read a file from a sensitive location
sensitive_data = ""

with open(join(RESTRICTED_DIR, RESTRICTED_FILE), mode='r') as fr:
    sensitive_data = fr.read()

# Write sensitive data to an unsafe location
UNSAFE_LOCATION = "/home/cs4440/unsafe-location"

with open(join(UNSAFE_LOCATION, RESTRICTED_FILE), mode='w') as fw:
    fw.write(sensitive_data)

print("Data exfiltration was successful!")