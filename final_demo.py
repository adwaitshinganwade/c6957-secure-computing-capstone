import subprocess


def main():
    # Run ausearch periodically with the checkpoint option to process previously unseen audit events
    while True:
        try:
            subprocess.run(["sudo", "ausearch", "-i", "--checkpoint", "exfil-demo.checkpoint", ">>", "auditd-logs/logs"], capture_output=False, text=False)
        except KeyboardInterrupt:
            print("Aborting...")
            exit()

if __name__ == "__main__":
    main()