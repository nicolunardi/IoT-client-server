from socket import *
import sys
from threading import Thread, active_count
import json
from data_templates import templates

FORMAT = "utf-8"
SERVER_IP = "127.0.0.1"
BUFF_SIZE = 1024


class Server:
    def __init__(self, port, attempts):
        self.port = port
        self.attempts = attempts
        self.address = (SERVER_IP, self.port)
        self.server_socket = socket(AF_INET, SOCK_STREAM)

        self.start()

    def start(self):
        # set up the socket and start listening for incoming connections
        self.server_socket.bind(self.address)
        self.server_socket.listen(5)
        print(f"listening on port {self.port}")

        # accept incoming connections
        self.receive_client()
        # self.server_socket.close()

    def receive_client(self):
        while True:
            try:
                print(active_count())
                client_socket, client_address = self.server_socket.accept()
                client_thread = ClientThread(client_address, client_socket)
                client_thread.start()
            except Exception as e:
                print("woops")


class ClientThread(Thread):
    def __init__(self, client_address: tuple, client_socket: socket):
        Thread.__init__(self)
        self.client_address = client_address
        self.client_socket = client_socket
        self.is_active = True
        self.is_auth = False

    def run(self):
        while self.is_active:
            # get the data and convert to a python dict
            client_data = self.receive_data()
            print("here", client_data)
            # initial interaction. first command after connection established
            if client_data["command"] == "SYN":
                self.handle_auth()

            if client_data == "FIN":
                self.is_active = False
                break

    # receive data in chunks and return the complete data
    def receive_data(self) -> dict:
        client_data = b""
        while True:
            # try:
            #     chunk = self.client_socket.recv(BUFF_SIZE)
            #     client_data += chunk
            #     if len(chunk) < BUFF_SIZE:
            #         print(json.loads(client_data))
            #         return json.loads(client_data)
            # except Exception:
            #     print("[Server]: Error encountered")
            #     return templates["ERR"]["message"]
            chunk = self.client_socket.recv(BUFF_SIZE)
            client_data += chunk
            if len(chunk) < BUFF_SIZE:
                print(json.loads(client_data))
                return json.loads(client_data)

    def handle_auth(self):
        self.send_data(templates["SYN_OK"])
        while True:
            client_data = self.receive_data()
            if client_data["command"] == "ERR":
                self.handle_close()
                return

    # sends data to client. converts dict to json string and then to bytes
    def send_data(self, data):
        self.client_socket.sendall(json.dumps(data).encode())

    def handle_close(self):
        print("[Server]: closing connection to client")


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
        or (not (argv[2].isdigit()) or not (1 <= int(argv[2]) <= 5))
    ):
        print(
            "Correct usage: python3 server.py [server_port] [number_of_failed_attempts]"
        )
        correct_usage = False

    return correct_usage


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print("Server is shutting down...")
        sys.exit(0)
