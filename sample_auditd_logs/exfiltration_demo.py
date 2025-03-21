import subprocess
from log_filter import process_event_sequence, split_logs_into_event_sequences


def main():
    # Run ausearch periodically with the checkpoint option to process previously unseen audit events
    while True:
        exec_result = subprocess.run(["ausearch", "-i", "--checkpoint", "exfil-demo.checkpoint"], capture_output=True, text=True)
        events_sequences = split_logs_into_event_sequences(exec_result.stdout)
        for event_sequence in events_sequences:
            process_event_sequence(event_sequence)

if __name__ == "__main__":
    main()