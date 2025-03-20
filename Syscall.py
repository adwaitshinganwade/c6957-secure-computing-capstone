class Syscall:
    def __init__(self, type, pid, ppid, a0, a1, a2, a3, command):
        self.type = type
        self.pid = pid
        self.ppid = ppid
        self.a0 = a0
        self.a1 = a1
        self.a2 = a2
        self.a3 = a3
        self.command = command