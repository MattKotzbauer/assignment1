#!/usr/bin/env python3
import socket
import selectors
import types

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self._setup_listening_socket()

    def _setup_listening_socket(self):
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.bind((self.host, self.port))
        self.lsock.listen()
        print(f"Listening on {(self.host, self.port)}")
        self.lsock.setblocking(False)
        self.sel.register(self.lsock, selectors.EVENT_READ, data=None)

    def run(self):
        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        # A new client is connecting.
                        self.accept_connection(key.fileobj)
                    else:
                        # A client socket is ready for I/O.
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    def accept_connection(self, sock: socket.socket):
        conn, addr = sock.accept()
        print(f"Accepted connection from {addr}")
        conn.setblocking(False)
        # Create a simple namespace to hold connection data.
        data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn, events, data=data)

    def service_connection(self, key, mask):
        sock = key.fileobj
        data = key.data
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Adjust buffer size as needed
            if recv_data:
                # Append to input buffer.
                data.inb += recv_data
                # For this simple example, assume each recv is a complete packet.
                self.handle_packet(data.inb, sock)
                data.inb = b""  # Clear the buffer after processing.
            else:
                print(f"Closing connection to {data.addr}")
                self.sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            if data.outb:
                try:
                    sent = sock.send(data.outb)
                    data.outb = data.outb[sent:]
                except BlockingIOError:
                    # If the socket is not ready for sending, try again later.
                    pass

    def handle_packet(self, packet_content: bytes, client_socket: socket.socket):
        """
        Process the incoming packet. This function is called when the server
        receives data from a client.
        """
        try:
            message = packet_content.decode("utf-8")
        except UnicodeDecodeError:
            message = ""
        print(f"Handling packet from {client_socket.getpeername()}: {message}")

        # Parse the message: For demonstration, we recognize two commands.
        words = message.split()
        if words:
            if words[0] == "count":
                # Count the number of words after the command.
                response_text = str(len(words[1:]))
            elif words[0] == "translate":
                # Translate the rest of the message to Pig Latin.
                response_text = self.trans_to_pig_latin(" ".join(words[1:]))
            else:
                # Default action: echo back the received message.
                response_text = f"Received: {message}"
        else:
            response_text = "Empty packet received"

        # Call response_packet to send the response.
        self.response_packet(response_text.encode("utf-8"), client_socket)

    def response_packet(self, packet_content: bytes, client_socket: socket.socket):
        """
        Queue a response packet to be sent back to the client.
        """
        try:
            key = self.sel.get_key(client_socket)
            # Append the packet to the client's output buffer.
            key.data.outb += packet_content
        except Exception as e:
            print("Error sending response:", e)

    def trans_to_pig_latin(self, text: str) -> str:
        """
        A simple helper that converts each word into a "pig latin" version.
        For each word, move the first letter to the end and append "ay".
        """
        words = text.split()
        pig_latin_words = []
        for word in words:
            if len(word) > 0 and word.isalpha():
                pig_word = word[1:] + word[0] + "ay"
            else:
                pig_word = word  # Leave punctuation/numbers unchanged.
            pig_latin_words.append(pig_word)
        return " ".join(pig_latin_words)

if __name__ == "__main__":
    HOST = "127.0.0.1"  # or '' to accept connections on all available IPv4 interfaces
    PORT = 65432
    server = Server(HOST, PORT)
    server.run()
    
