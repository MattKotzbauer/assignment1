#!/usr/bin/env python3
import socket

def send_request(sock: socket.socket, packet_content: bytes) -> bytes:
    """
    Sends a request over an already-open socket and waits for the response.
    """
    sock.sendall(packet_content)
    # In a more robust implementation, you would loop until a full message is received.
    response = sock.recv(1024)
    return response

def main():
    HOST = "127.0.0.1"  # Server address
    PORT = 65432        # Server port

    # Create one persistent connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("Connected to server. Type your commands or 'exit' to quit.")
        while True:
            command = input("> ")
            if command.lower() == "exit":
                print("Exiting session.")
                break
            response = send_request(sock, command.encode("utf-8"))
            print("Response from server:", response.decode("utf-8"))

if __name__ == "__main__":
    main()
