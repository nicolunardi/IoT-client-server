from socket import *
import base64
import sys
import os
import json
from threading import Thread
from math import ceil
from time import sleep
from data_templates import templates

FORMAT = "utf-8"
UDP_CHUNK_SIZE = 1024
BUFF_SIZE = 2048
TIMEOUT = 3
device_name = ""


class UdpSocketThread(Thread):
    def __init__(
        self,
        port,
    ):
        Thread.__init__(self)
        self.address = ("", port)
        self.udp_socket = socket(AF_INET, SOCK_DGRAM)
        self.udp_socket.settimeout(TIMEOUT)

    def run(self):
        try:
            # set up the socket and start listening for incoming connections
            self.udp_socket.bind(self.address)
            print("udp server running")
            while True:
                self.receive_udp_file()
        except KeyboardInterrupt:
            self.udp_socket.close()

    def send_file(self, filename, address):
        try:
            # send the file information
            message = {
                "owner": device_name,
                "filename": filename,
            }
            self.udp_socket.sendto(
                json.dumps(message).encode(),
                address,
            )
            with open(f"client/{filename}", "rb") as file:
                while True:
                    chunk = file.read(UDP_CHUNK_SIZE)
                    if not chunk:
                        break
                    # throttle the transmission
                    sleep(0.005)

                    self.udp_socket.sendto(
                        chunk,
                        address,
                    )
        # UVF test1 example2.mp4
        except FileNotFoundError:
            print("no file exists with that filename")
            return

    def receive_udp_file(self):
        data = {}
        total_chunks = 0
        filename = ""
        owner = ""
        full_file = b""

        while True:
            self.udp_socket.settimeout(1)
            try:
                message, address = self.udp_socket.recvfrom(BUFF_SIZE)
                self.udp_socket.settimeout(TIMEOUT)
                print(message)

                try:
                    # get information about the file
                    decoded_message = json.loads(message)
                    filename = decoded_message["filename"]
                    owner = decoded_message["owner"]
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # if its not a json format then its the files raw bites
                    full_file += message

            # when no more chunks are coming in
            except timeout:
                if full_file:
                    with open(f"client/{owner}-{filename}", "wb") as file:
                        file.write(full_file)


def main(argv):
    # ensure the user is using the program correctly
    if not verify_correct_usage(argv):
        return

    print("Welcome!")

    server_ip = argv[1]
    server_port = int(argv[2])
    client_udp_port = int(argv[3])

    # create a socket and establish a connection to the server
    client_socket = create_tcp_socket((server_ip, server_port))
    # initialize authentication
    handle_auth(client_socket)
    # initialize udp socket
    udp_socket = UdpSocketThread(client_udp_port)
    udp_socket.daemon = True
    udp_socket.start()

    # upon successful authentication, send the UDP port to the server
    send_udp_port(client_udp_port, client_socket)

    handle_commands(client_socket, udp_socket)


def verify_correct_usage(argv):
    correct_usage = True

    # check that the correct number of arguments have been provided
    # also check that the port numbers given are in the correct range
    if (
        len(argv) != 4
        or (not (1024 <= int(argv[2]) <= 65353))
        or (not (1024 <= int(argv[3]) <= 65353))
    ):
        print(
            "Correct usage: python3 client.py [server_ip] [server_port] [client_udp_server_port]"
        )
        correct_usage = False

    return correct_usage


# creates a TCP socket and connects it to the server
def create_tcp_socket(address):
    # create the TCP socket
    client_socket = socket(AF_INET, SOCK_STREAM)

    print("Attempting to connect to server...")
    # establish the connection with the server
    try:
        client_socket.connect(address)
    except ConnectionRefusedError:
        print(
            f"Failed to connect to the server at IP {address[0]} on port {address[1]}"
        )
        sys.exit(1)

    return client_socket


# get credentials from user
def get_credentials():
    valid = False
    username = ""
    password = ""
    while not valid:
        username = input("Username: ")
        # ensure username is not blank and has no whitespace
        if not len(username) or (len(username.split()) > 1):
            print(
                "Username must not be blank or have any whitespace. Please type a valid username."
            )
        else:
            valid = True

    valid = False
    while not valid:
        password = input("Password: ")
        # ensure password is not blank and has no whitespace
        if not len(password) or (len(password.split()) > 1):
            print(
                "Password must not be blank or have any whitespace. Please type a valid password."
            )
        else:
            valid = True

    return (username.strip(), password)


def handle_commands(client_socket: socket, udp_socket):
    commands = ["EDG", "UED", "SCS", "DTE", "AED", "UVF", "OUT"]
    while True:
        user_input = input(
            "Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT): "
        ).split()
        # ensure a valid command is entered
        command = user_input[0]
        if not command in commands:
            print("Error. Invalid command!")
        else:
            if command == "EDG":
                handle_edg(user_input)
            elif command == "UED":
                handle_ued(user_input, client_socket)
            elif command == "SCS":
                handle_scs(user_input, client_socket)
            elif command == "AED":
                handle_aed(client_socket)
            elif command == "DTE":
                handle_dte(user_input, client_socket)
            elif command == "UVF":
                handle_uvf(user_input, udp_socket, client_socket)

            elif command == "OUT":
                handle_out(client_socket)


def handle_auth(client_socket: socket):
    # create auth object template
    auth_data = templates["AUTH"]
    # send initial data to let server know the client is ready for auth
    send_data(templates["SYN"], client_socket)
    # get the response from the server
    server_data = receive_data(client_socket)
    # ok to begin authentication
    if server_data["command"] == "SYN_OK":
        print(server_data["message"])
        # get the username and password from the user
        username, password = get_credentials()
        # send the data to the server with credentials
        auth_data["data"]["username"] = username
        auth_data["data"]["password"] = password
        send_data(auth_data, client_socket)
        while True:
            server_data = receive_data(client_socket)
            # server says credentials match and everything is ok
            if server_data["command"] == "AUTH_OK":
                global device_name
                device_name = username
                print(server_data["message"])
                return
            # something wrong with the password
            elif server_data["command"] == "AUTH_INV_PASS":
                print(server_data["message"])
                # get a new password from the user and update the auth_data object
                password = get_password()
                auth_data["data"]["password"] = password
                send_data(auth_data, client_socket)
            # maximum amount of password tries have been reached. Close the program
            elif server_data["command"] == "AUTH_INV_PASS_MAX":
                print(server_data["message"])
                exit_program(client_socket)
            # Username doesn't match any on record
            elif server_data["command"] == "AUTH_INV_USER":
                print(server_data["message"])
                # get a new username and password from the user and update the auth_data object
                username = get_username()
                auth_data["data"]["username"] = username
                auth_data["data"]["password"] = get_password()
                send_data(auth_data, client_socket)
            elif server_data["command"] == "AUTH_INV_BAN":
                print(server_data["message"])
                exit_program(client_socket)


# sends data to server. Converts dict to json string and then to bytes
def send_data(data, client_socket):
    client_socket.sendall(json.dumps(data).encode())


def receive_data(client_socket: socket):
    server_data = b""
    while True:
        chunk = client_socket.recv(BUFF_SIZE)
        server_data += chunk
        if len(chunk) < BUFF_SIZE:
            return json.loads(server_data)


# ask user to input the password again. Used when server indicates password doesn't match
def get_password():
    valid = False
    password = ""
    while not valid:
        password = input("Password: ")
        # ensure password is not blank and has no whitespace
        if not len(password) or (len(password.split()) > 1):
            print(
                "Password must not be blank or have any whitespace. Please type a valid password."
            )
        else:
            valid = True

    return password


def get_username():
    valid = False
    username = ""
    while not valid:
        username = input("Username: ")
        # ensure username is not blank and has no whitespace
        if not len(username) or (len(username.split()) > 1):
            print(
                "Username must not be blank or have any whitespace. Please type a valid username."
            )
        else:
            valid = True

    # remove leading and trailing whitespace
    return username.strip()


def send_udp_port(udp_port: int, client_socket: socket):
    udp_data = templates["UDP"]
    udp_data["data"] = udp_port
    send_data(udp_data, client_socket)


def handle_edg(user_input):
    if len(user_input) != 3:
        print("Correct usage: EDG [fileID] [dataAmount]")
        return

    _, file_id, data_amount = user_input
    # ensure arguments are integers and that id is >= 0 and amount is > 0
    if (not file_id.isdigit() or not data_amount.isdigit()) or (
        not int(file_id) >= 0 or not int(data_amount) > 0
    ):
        print("fileID and DataAmount must be integers of the form:")
        print("fileID >= 0, dataAmount > 0")
    else:
        filename = f"{device_name}-{file_id}.txt"
        print(f"The edge device is generating {data_amount} data samples...")

        with open(f"client/{filename}", "w") as file:
            for i in range(int(data_amount)):
                file.write(f"{i}\n")
        print(
            f"Data generation done, {data_amount} data samples have been generated and stored in the file {filename}"
        )


def handle_ued(user_input, client_socket: socket):
    if len(user_input) != 2:
        print("Correct usage: UED [fileID]")
        return

    file_id = user_input[1]
    filename = f"{device_name}-{file_id}"
    data = []
    try:
        with open(f"client/{filename}.txt", "r") as file:
            for line in file:
                data.append(line)
        message = templates["UED"]
        message["data"] = data
        message["file_id"] = file_id
        send_data(message, client_socket)
        server_message = receive_data(client_socket)
        print(server_message["message"])
    except FileNotFoundError:
        print("a file with that ID does not exist. Please try another ID")


def handle_scs(user_input, client_socket: socket):
    computations = ("SUM", "AVERAGE", "MIN", "MAX")
    if len(user_input) != 3:
        print("correct usage: SCS [fileID] [computation]")
        return

    # TODO check that the fileid is an int
    file_id = user_input[1]
    computation = user_input[2]

    # check the computation requested is valid
    if not computation in computations:
        print("invalid computation. Please choose from one of the following:")
        print("    SUM, AVERAGE, MIN, MAX")
        return

    message = templates["SCS"]
    message["data"] = [file_id, computation]

    send_data(message, client_socket)
    response = receive_data(client_socket)
    print(response["message"])


def handle_dte(user_input, client_socket: socket):
    file_id = user_input[1]
    if len(user_input) != 2:
        print("correct usage: DTE [fileID]")
        return
    if not file_id.isdigit():
        print("fileID must be an integer")
        return

    message = templates["DTE"]
    message["data"] = file_id

    send_data(message, client_socket)
    response = receive_data(client_socket)
    print(response["message"])


def handle_uvf(user_input, udp_socket: UdpSocketThread, client_socket: socket):
    if len(user_input) != 3:
        print("correct usage: UVF [deviceName] [filename]")
        return

    _, device_name, filename = user_input

    if not os.path.exists(f"client/{filename}"):
        print(f"a file with the file name '{filename}' does not exist")
        return

    device_data = None
    # dont print the devices on the terminal
    active_devices = handle_aed(client_socket, display=False)

    if not active_devices:
        print("that device is not currently active. please try again later.")
        return

    # check the device the user wants to send a file to is active
    for device in active_devices:
        if device[2] == device_name:
            device_data = device

    if not device_data:
        print("that device is not currently active. please try again later.")
        return

    device_address = (device_data[3], int(device_data[4]))
    udp_socket.send_file(filename, device_address)


# prints the active devices to the terminal and returns the list of active devices
# for use in UVF
def handle_aed(client_socket: socket, display=True):
    send_data(templates["AED"], client_socket)
    response = receive_data(client_socket)
    if display:
        print(response["message"])
    return response["data"]


def handle_out(client_socket: socket):
    send_data(templates["OUT"], client_socket)
    data = receive_data(client_socket)
    if data["command"] == "OUT_OK":
        print(data["message"])
        client_socket.close()
        sys.exit(0)


# send the out command to the server, close the TCP connection and exit the program
def exit_program(client_socket: socket):
    send_data(templates["OUT"], client_socket)
    client_socket.close()
    sys.exit()


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print()
        print("shutting down...")
        sys.exit(0)
