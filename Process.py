class Process:
    def __init__(self, pid, ppid=None, sensitive=False):
        self.pid = pid
        self.ppid = ppid
        self.sensitive = sensitive
        self.children = list()

    def mark_process_sensitive(self):
        self.sensitive = True

    def is_process_sensitive(self):
        return self.sensitive

