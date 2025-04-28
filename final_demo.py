import subprocess


def main():
    # Run ausearch periodically with the checkpoint option to process previously unseen audit events
    with open("auditd-logs/logs") as logfile:
        while True:
            try:
                subprocess.run(["sudo", "ausearch", "-i", "-k", "exfil-final-demo", "--checkpoint", "exfil-demo.checkpoint"], capture_output=True, text=True, stdout=logfile)
            except KeyboardInterrupt:
                print("Aborting...")
                exit()

if __name__ == "__main__":
    main()