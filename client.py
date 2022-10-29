from http import server
from socket import *
import sys
import json
from data_templates import templates

FORMAT = "utf-8"
BUFF_SIZE = 1024


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
    # get credentials from the client. uses basic validation
    username, password = get_credentials()

    handle_commands(client_socket)


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
    print("Please enter your credentials for authentication purposes.")
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


def handle_commands(client_socket: socket):
    while True:
        data = input("please type something: ")
        client_socket.sendall(data.encode())
        server_data = b""
        while True:
            chunk = client_socket.recv(BUFF_SIZE)
            server_data += chunk
            if len(chunk) < BUFF_SIZE:
                break

        print(server_data.decode(FORMAT))


def handle_auth(client_socket: socket):
    # create auth object template
    auth_data = templates["AUTH"]
    # send initial data to let server know the client is ready for auth
    send_data(templates["SYN"], client_socket)
    # get the response from the server
    while True:
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
            server_data = receive_data(client_socket)
            # server says credentials match and everything is ok
            if server_data["command"] == "AUTH_OK":
                print(server_data["message"])
                return
            # something wrong with the password
            elif server_data["command"] == "AUTH_INV_PASS":
                print(server_data["message"])
                # get a new password from the user and update the auth_data object
                password = get_password()
                auth_data["data"]["password"] = password
                send_data(auth_data, client_socket)
            # Username doesn't match any on record
            elif server_data["command"] == "AUTH_INV_USER":
                print(server_data["message"])
                # get a new username and password from the user and update the auth_data object
                auth_data["data"]["username"] = get_username()
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
    valid = True
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


# send the out command to the server, close the TCP connection and exit the program
def exit_program(client_socket: socket):
    send_data(templates["OUT"], client_socket)
    client_socket.close()
    sys.exit()


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print("shutting down...")
        sys.exit(0)
