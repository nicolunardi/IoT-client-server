from socket import *
import sys


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

    # get credentials from the client. uses basic validation
    username, password = get_credentials()


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
    username = ""
    password = ""
    print("Please enter your credentials for authentication purposes.")
    while not len(username):
        username = input("Username: ")
        if not len(username):
            print("Username must not be blank. Please type a valid username.")

    while not len(password):
        password = input("Password: ")
        if not len(password):
            print("Password must not be blank. Please type a valid password.")

    return (username, password)


if __name__ == "__main__":
    main(sys.argv)
