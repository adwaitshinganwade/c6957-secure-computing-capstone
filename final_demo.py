import subprocess
import time

def main():
    # Run ausearch periodically with the checkpoint option to process previously unseen audit events
    with open("auditd-logs/logs", "a") as logfile:
        while True:
            print("Polling new records...\n")
            try:
                subprocess.run(["sudo", "ausearch", "-i", "--checkpoint", "exfil-demo.checkpoint"], text=True, stdout=logfile)
                time.sleep(5)
            except KeyboardInterrupt:
                print("Aborting...")
                exit()

if __name__ == "__main__":
    main()