import time

from pygtail import Pygtail

class AuditLogMonitor:
    """
    AuditLogMonitor provides the scaffolding for designing an event-driven log processor. An
    instance of :class:`AuditLogMonitor` can be configured to "follow" a specific log file. 
    It can also be told how it should separate events in the file. The :method:`monitor(event_callback)` method
    provides the infrastructure necessary to keep reading previously unread contents from the provided log file.
    """
    def __init__(self, log_file: str, log_event_delimiter: str = "----"):
        """
        Creates an instance of :class:`AuditLogMonitor` that reads logs from a log
        file located at :attr:`log_file` and treats the character sequence :attr:`log_event_delimiter`
        as a string that demarcates two log events.
        <br> <b>NOTE</b>: A log event is a collection of logs that represents a single audit event. 
        This notion is based on the manner in which `auditd` records events. Typically, each `auditd` log
        event is composed of one or more strings (each ending in a new-line character), with two such events separated by
        a delimiter, typically `----`.
        """
        self.__log_file = log_file
        self.__log_event_delimiter = log_event_delimiter


    def __split_logs_into_event_sequences(self, logs: str) -> [str]:
        """
        Splits raw event logs collected using auditd into individual events based on the delimiter "----".
        :param logs: A string which holds logs processed using ausearch
        :return: List of individual events.
        """
        return logs.split(self.__log_event_delimiter)

    def __fetch_new_logs(self) -> str:
        """
        Reads any new lines appended to the file :attr:`__log_file` since the last time
        it was read and returns unread lines of text as a string (preserving the original
        line separator)
        """
        new_logs = ""
        for line in Pygtail(self.__log_file):
            new_logs += line
        return new_logs
    
    def monitor(self, event_callback):
        """
        Keep monitoring logs recorded in :attr:`self.__log_file`. Keeps tailing this file,
        and splits logs read in each iteration into events based on :attr:`self.__log_event_delimiter`. 
        Each event (a string) is passed as an argument to :attr:`event_callback`.
        """
        while True:
            # TODO - incomplete event sequences
            new_logs = self.__fetch_new_logs()
            event_sequences = self.__split_logs_into_event_sequences(new_logs)
            for event in event_sequences:
                event_callback(event)
            time.sleep(10)


# TODO - Only for testing. Delete later.
if __name__ == "__main__":
    am = AuditLogMonitor("sample_auditd_logs/handful_logs")
    am.monitor()