from queue import Queue
from socket import *
import sys
from threading import Thread, active_count
import json
from datetime import datetime
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
        self.queue = Queue()
        self.user_attempts = {}

        self.start()

    def start(self):
        # TODO create all the files from scratch when server boots
        try:
            # set up the socket and start listening for incoming connections
            self.server_socket.bind(self.address)
            self.server_socket.listen(5)
            print(f"listening on port {self.port}")

            # create a file writer thread
            self.initialize_file_writer()

            # accept incoming connections
            self.receive_client()
            # self.server_socket.close()
        except KeyboardInterrupt:
            self.close_server()

    # create and initialize the file writer thread
    def initialize_file_writer(self):
        file_writer = FileWriter(self)
        file_writer.daemon = True
        file_writer.start()

    def receive_client(self):
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_thread = ClientThread(
                    client_address, client_socket, self
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                # TODO
                pass

    def get_user_attempts(self):
        return self.user_attempts

    def get_attempts_by_user(self, user):
        if not user in self.user_attempts:
            # create the user in the attempts object if not present
            self.create_user_attempt_entry(user)

        return self.user_attempts[user]

    def set_user_attempts(self, user, value):
        self.user_attempts[user] = value

    # checks if a user is banned
    def is_user_banned(self, user):
        if not user in self.user_attempts:
            self.create_user_attempt_entry(user)
        # create the object for the user
        if self.user_attempts[user]["banned"]:
            time_since_ban = (
                datetime.now() - self.user_attempts[user]["time"]
            ).seconds
            if time_since_ban < 10:
                self.user_attempts[user]["banned"] = True
            else:
                self.user_attempts[user]["banned"] = False
        return self.user_attempts[user]["banned"]

    def create_user_attempt_entry(self, user):
        self.user_attempts[user] = {
            "attempts": 0,
            "banned": False,
            "time": datetime.now(),
        }

    # get a formatted string representing the date
    def format_date(self, date: datetime):
        return date.strftime("%d %B %Y %H:%M:%S")

    # get datetime object from a formatted string
    def get_date_from_str(self, date: str):
        return datetime.strptime(date, "%d %B %Y %H:%M:%S")

    def close_server(self):
        print()
        print("Server is shutting down...")
        self.server_socket.close()
        sys.exit(0)


class ClientThread(Thread):
    def __init__(
        self, client_address: tuple, client_socket: socket, server: Server
    ):
        Thread.__init__(self)
        self.client_address = client_address
        self.client_socket = client_socket
        self.is_active = True
        self.attempts = 0
        self.server = server
        self.client_name = ""

    def run(self):
        while self.is_active:
            try:
                # get the data and convert to a python dict
                client_data = self.receive_data()
                # initial interaction. first command after connection established
                if client_data["command"] == "SYN":
                    self.handle_auth()
                elif client_data["command"] == "UDP":
                    self.handle_receive_udp_info(client_data)
                # terminate the thread
                elif client_data["command"] == "OUT":
                    self.handle_close()
                    return

                if client_data == "FIN":
                    self.is_active = False
                    break
            except Exception as e:
                print(e.message)
                self.handle_close()
                self.is_active = False

    # receive data in chunks and return the complete data
    def receive_data(self) -> dict:
        client_data = b""
        while True:
            chunk = self.client_socket.recv(BUFF_SIZE)
            client_data += chunk
            if len(chunk) < BUFF_SIZE:
                print(json.loads(client_data))
                return json.loads(client_data)

    def handle_auth(self):
        self.send_data(templates["SYN_OK"])

        while True:
            client_data = self.receive_data()
            if client_data["command"] == "AUTH":
                username = client_data["data"]["username"]
                password = client_data["data"]["password"]
                # check the validity of the credentials
                validity = self.verify_credentials((username, password))
                if validity == "AUTH_OK":
                    if self.server.is_user_banned(username):
                        self.send_data(templates["AUTH_INV_BAN"])
                        raise ClientBannedException
                    else:
                        self.client_name = username
                        self.send_data(templates["AUTH_OK"])
                    return
                elif validity == "AUTH_INV_PASS":
                    # check to see if the user has been banned
                    if self.server.is_user_banned(username):
                        self.send_data(templates["AUTH_INV_BAN"])
                    else:
                        # check how many incorrect attempts have been made and update the object
                        user_attempts_object = self.server.get_attempts_by_user(
                            username
                        )
                        if (
                            user_attempts_object["attempts"]
                            < self.server.attempts
                        ):
                            if (
                                user_attempts_object["attempts"]
                                == self.server.attempts - 1
                            ):
                                user_attempts_object["attempts"] = 0
                                user_attempts_object["banned"] = True
                                user_attempts_object["time"] = datetime.now()
                                self.send_data(templates["AUTH_INV_PASS_MAX"])
                            else:
                                user_attempts_object["attempts"] += 1
                                self.send_data(templates["AUTH_INV_PASS"])

                            # update the user attempts object based on new values
                            self.server.set_user_attempts(
                                username, user_attempts_object
                            )
                elif validity == "AUTH_INV_USER":
                    self.send_data(templates["AUTH_INV_USER"])

    # sends data to client. converts dict to json string and then to bytes
    def send_data(self, data):
        print("sending, ", data)
        self.client_socket.sendall(json.dumps(data).encode())

    def handle_close(self):
        print(
            f"Closing connection to client on {self.client_address} with device name {self.client_name}"
        )
        response = templates["OUT_OK"]
        response["message"] = f"Goodbye, {self.client_name}"
        self.send_data(response)

    # checks the credentials file against the credentials provided by the user.
    # credentials is a tuple of the form (username, password)
    def verify_credentials(self, credentials: tuple):
        with open("server/credentials.txt") as file:
            for line in file:
                username, password = line.split()
                if username == credentials[0]:
                    if password == credentials[1]:
                        return "AUTH_OK"
                    else:
                        return "AUTH_INV_PASS"
        return "AUTH_INV_USER"

    # take the udp port number and add a task to teh queue. The file writer will then
    # handle writing the information to the file
    def handle_receive_udp_info(self, client_data):
        udp_port = client_data["data"]
        timestamp = self.server.format_date(datetime.now())
        new_task = {
            "task": "UDP_UPLOAD",
            "data": (
                timestamp,
                self.client_name,
                self.client_address[0],
                udp_port,
            ),
        }
        self.server.queue.put(new_task)


class FileWriter(Thread):
    def __init__(self, server: Server):
        Thread.__init__(self)
        self.server = server

    # some code taken from the official python site on how to use Queue
    # https://docs.python.org/3/library/queue.html
    def run(self):
        try:
            while True:
                if not self.server.queue.empty():
                    task = self.server.queue.get()
                    self.handle_tasks(task)
        except (KeyboardInterrupt, SystemExit):
            return

    def handle_tasks(self, task):
        if task["task"] == "UDP_UPLOAD":
            self.handle_udp_upload(task["data"])

    def handle_udp_upload(self, data):
        timestamp, device_name, device_ip, udp_port = data
        with open("server/cse-edge-device-log.txt", "r+") as file:
            # get the last sequence number
            highest_sequence = len(file.readlines())
            file.write(
                f"{highest_sequence + 1}; {timestamp}; {device_name}; {device_ip}; {udp_port} \n"
            )


class ClientBannedException(Exception):
    pass


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
        sys.exit(0)
