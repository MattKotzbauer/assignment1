# server.py
import socket
import selectors
import types
from typing import Dict, Optional
import driver
from core_entities import Message, User

class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 65432):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.sock = None
        self.connections: Dict[socket.socket, types.SimpleNamespace] = {}

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Add socket reuse option to avoid "address already in use"
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen()
        print(f"Listening on {(self.host, self.port)}")
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, data=None)

    def run(self):
        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self._accept_connection(key.fileobj)
                    else:
                        self._handle_client_socket(key, mask)
        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()
            if self.sock:
                self.sock.close()

    def _accept_connection(self, sock: socket.socket):
        conn, addr = sock.accept()
        print(f"Accepted connection from {addr}")
        conn.setblocking(False)
        data = types.SimpleNamespace(
            addr=addr,
            inb=b"",
            outb=b""
        )
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn, events, data=data)
        self.connections[conn] = data

    def _handle_client_socket(self, key: selectors.SelectorKey, mask: int):
        sock = key.fileobj
        data = key.data

        if mask & selectors.EVENT_READ:
            try:
                recv_data = sock.recv(1024)
                if recv_data:
                    data.inb += recv_data
                    self.handle_packet(recv_data, sock)
                else:
                    # Only close if we actually got an empty message (client disconnected)
                    print(f"Client {data.addr} disconnected")
                    self._close_connection(sock)
            except Exception as e:
                print(f"Error handling client socket: {e}")
                self._close_connection(sock)

        if mask & selectors.EVENT_WRITE and data.outb:
            try:
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
            except Exception as e:
                print(f"Error sending data to client: {e}")
                self._close_connection(sock)

    def _close_connection(self, sock: socket.socket):
        addr = self.connections[sock].addr if sock in self.connections else "Unknown"
        print(f"Closing connection to {addr}")
        self.sel.unregister(sock)
        sock.close()
        if sock in self.connections:
            del self.connections[sock]

    def response_packet(self, packet_content: bytes, client_socket: socket.socket):
        try:
            if client_socket in self.connections:
                self.connections[client_socket].outb += packet_content
        except Exception as e:
            print(f"Failed to queue response: {e}")

    def handle_packet(self, packet_content: bytes, client_socket: socket.socket):
        try:
            if len(packet_content) < 7:
                print("Received packet is too short.")
                return

            # packet_length: denotes total length of packet
            packet_length = int.from_bytes(packet_content[0:4], byteorder='big')
            # opcode: denotes type of request
            opcode = packet_content[4]
            
            if opcode == 0x01:
                username_length = int.from_bytes(packet_content[5:7], byteorder='big')
                username = packet_content[7:7+username_length].decode('utf-8')
                user_exists = driver.user_trie.trie.get(username) is not None
                status = 0x01 if user_exists else 0x00
                print(f"Username '{username}' exists: {user_exists}. Sending status code {status:#04x}.")
                # Response format:
                #   1. Length (4 bytes) for the packet body (here: opcode + status = 1 + 1 = 2 bytes)
                #   2. Opcode 0x02 (1 byte)
                #   3. Status code (1 byte)
                response_body = bytes([0x02, status])
                response_length = len(response_body).to_bytes(4, byteorder='big')
                full_response = response_length + response_body

                self.response_packet(full_response, client_socket)

            elif opcode == 0x03:
                pass
            elif opcode == 0x05:
                pass
            elif opcode == 0x07:
                pass
            # ... TODO: next opcodes ...
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    user_john = User(1, "john", "foo")
    driver.user_trie.trie.add("john", user_john)
    sample = driver.user_trie.trie.get("john")
    print(sample)
    # server = Server()
    # server.start()
    # server.run()
