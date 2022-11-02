from math import inf
from queue import Queue
from socket import *
import sys
from threading import Thread
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
        print("server is shutting down...")
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
                elif client_data["command"] == "UED":
                    self.handle_ued(client_data)
                elif client_data["command"] == "SCS":
                    self.handle_scs(client_data)
                # terminate the thread
                elif client_data["command"] == "OUT":
                    self.handle_close()
                    return

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
                # print(json.loads(client_data))
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
                        print(f"{username} has connected from address {self.client_address[0]}")
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
        # print("sending, ", data)
        self.client_socket.sendall(json.dumps(data).encode())

    def handle_close(self):
        print(
            f"closing connection to client on {self.client_address} with device name {self.client_name}"
        )
        new_task = {"task": "OUT", "data": (self.client_name)}
        self.server.queue.put(new_task)
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

    def handle_ued(self, client_data):
        # device_name, timestamp, fileid, dataamount
        data = client_data["data"]
        file_id = client_data["file_id"]
        data_amount = len(data)
        timestamp = self.server.format_date(datetime.now())
        new_task = {
            "task": "UED_UPLOAD",
            "data": (data, self.client_name, timestamp, file_id, data_amount),
        }
        self.server.queue.put(new_task)
        message = templates["UED_OK"]
        message[
            "message"
        ] = f"Server has received and uploaded {self.client_name}-{file_id}.txt"
        self.send_data(message)

    def handle_scs(self, client_data):
        file_id = client_data["data"][0]
        computation = client_data["data"][1]
        filename = f"{self.client_name}-{file_id}.txt"

        print(
            f"{self.client_name} requested a computation on the file with ID of {file_id}"
        )
        max = -inf
        min = inf
        count = 0
        sum = 0
        try:
            with open(f"server/{filename}", "r") as file:
                for line in file:
                    count += 1
                    number = int(line)
                    sum += number
                    if number > max:
                        max = number
                    if number < min:
                        min = number
        except FileNotFoundError:
            print(f"a file with the filename '{filename}' does not exist.")
            self.send_data(templates["SCS_INV"])
            return

        average = sum / count
        result = 0
        if computation == "MAX":
            result = max
        elif computation == "MIN":
            result = min
        elif computation == "AVERAGE":
            result = average
        elif computation == "SUM":
            result = sum

        response = templates["SCS_OK"]
        response[
            "message"
        ] = f"The {computation} on the file with ID of {file_id} is: {result}"
        self.send_data(response)


class FileWriter(Thread):
    def __init__(self, server: Server):
        Thread.__init__(self)
        self.server = server

    # some code taken from the official python site on how to use Queue
    # https://docs.python.org/3/library/queue.html
    def run(self):
        self.initialize_files()
        try:
            while True:
                if not self.server.queue.empty():
                    task = self.server.queue.get()
                    self.handle_tasks(task)
        except (KeyboardInterrupt, SystemExit):
            return

    def initialize_files(self):
        # open the file and erase the contents on start-up
        with open("server/cse-edge-device-log.txt", "w") as file1:
            pass

    def handle_tasks(self, task):
        if task["task"] == "UDP_UPLOAD":
            self.handle_udp_upload(task["data"])
        elif task["task"] == "UED_UPLOAD":
            self.handle_eud_upload(task["data"])
        elif task["task"] == "OUT":
            self.handle_close_client(task["data"])

    def handle_udp_upload(self, data):
        timestamp, device_name, device_ip, udp_port = data
        with open("server/cse-edge-device-log.txt", "r+") as file:
            # get the last sequence number
            highest_sequence = len(file.readlines())
            file.write(
                f"{highest_sequence + 1}; {timestamp}; {device_name}; {device_ip}; {udp_port}\n"
            )
            print("cse-edge-device-log.txt file has been updated")

    def handle_eud_upload(self, data):
        client_data, client_name, timestamp, file_id, data_amount = data
        filename = f"{client_name}-{file_id}.txt"
        with open(f"server/{filename}", "w") as file:
            for number in client_data:
                file.write(f"{number}")
        print(
            f"data file has been received from {client_name} and uploaded as {filename}"
        )
        with open("server/upload-log.txt", "a") as file:
            file.write(
                f"{client_name}; {timestamp}; {file_id}; {data_amount}\n"
            )
        print("upload-log.txt file has been updated")

    def handle_close_client(self, data):
        client_name = data
        active_devices = []
        with open("server/cse-edge-device-log.txt", "r+") as file:
            # write the file contents to memory without sequence numbers. exclude
            # the device being logged out
            for line in file:
                _, timestamp, device_name, device_ip, udp_port = line.split(
                    "; "
                )
                # skip device name logging out
                if device_name == client_name:
                    continue
                active_devices.append(
                    (timestamp, device_name, device_ip, udp_port)
                )
            # go back to start of the file
            file.truncate(0)
            file.seek(0, 0)
            # update sequence numbers
            for count, value in enumerate(active_devices):
                timestamp, device_name, device_ip, udp_port = value
                file.write(
                    f"{count + 1}; {timestamp}; {device_name}; {device_ip}; {udp_port}"
                )
            print("cse-edge-device-log.txt file has been updated")


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
            "correct usage: python3 server.py [server_port] [number_of_failed_attempts]"
        )
        correct_usage = False

    return correct_usage


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.exit(0)
