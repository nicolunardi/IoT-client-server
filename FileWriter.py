from threading import Thread


class FileWriter(Thread):
    def __init__(
        self, client_address: tuple, client_socket: socket, server: Server
    ):
        Thread.__init__(self)
        self.server = server

    def run(self):
        pass
