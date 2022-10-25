from socket import *
import sys


class Server:
    def __init__(self, port, attempts):
        self.port = port
        self.attempts = attempts
        self.address = (SERVER_IP, self.port)
        self.server_socket = socket(AF_INET, SOCK_STREAM)

        self.start()

    def start(self):
        self.server_socket.bind(self.address)
        self.server_socket.listen(5)
        print(f"listening on port {self.port}")
        print(self.server_socket)



def main(argv):
    if not verify_correct_usage(argv):
        return

    server_port = int(argv[1])
    number_failed_attempts = int(argv[2])

    # create the TCP socket on which to listen to connection from
    server_socket = Server(server_port, number_failed_attempts)


def verify_correct_usage(argv):
    correct_usage = True

    # check that the correct number of arguments have been provided
    # also check that the port number given and failed attempts are in the correct range
    if (
        len(argv) != 3
        or (not (1024 <= int(argv[1]) <= 65353))
        or (not (1 <= int(argv[2]) <= 5))
    ):
        print(
            "Correct usage: python3 server.py [server_port] [number_of_failed_attempts]"
        )
        correct_usage = False

    return correct_usage


if __name__ == "__main__":
    global SERVER_IP
    SERVER_IP = "127.0.0.1"
    main(sys.argv)
