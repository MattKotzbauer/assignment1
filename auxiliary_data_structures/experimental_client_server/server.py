


    # server.py
import socket
import selectors
import types
from typing import Dict, Optional

class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 65432):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.sock = None
        self.connections: Dict[socket.socket, types.SimpleNamespace] = {}

    def start(self):
        """Start the server and begin listening for connections."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen()
        print(f"Listening on {(self.host, self.port)}")
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, data=None)

    def run(self):
        """Main server loop."""
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
        """Accept a new client connection."""
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
        """Handle I/O events for a client socket."""
        sock = key.fileobj
        data = key.data

        if mask & selectors.EVENT_READ:
            try:
                recv_data = sock.recv(1024)
                if recv_data:
                    # Store incoming data in buffer
                    data.inb += recv_data
                    # Process the packet
                    self.handle_packet(recv_data, sock)
                else:
                    # Only close if we actually got an empty message (client disconnected)
                    self._close_connection(sock)
            except Exception as e:
                print(f"Error handling client socket: {e}")
                self._close_connection(sock)

    def _close_connection(self, sock: socket.socket):
        """Close a client connection and clean up."""
        print(f"Closing connection to {sock.getpeername()}")
        self.sel.unregister(sock)
        sock.close()
        if sock in self.connections:
            del self.connections[sock]

    def response_packet(self, packet_content: bytes, client_socket: socket.socket):
        """Send a response packet to a client."""
        try:
            client_socket.send(packet_content)
        except Exception as e:
            print(f"Failed to send response to client {client_socket.getpeername()}: {e}")
            self._close_connection(client_socket)

    def handle_packet(self, packet_content: bytes, client_socket: socket.socket):
        """Process incoming packets based on opcode."""
        try:
            opcode = packet_content[4]
            if opcode == 0x01:
                # Example: Echo the packet back
                self.response_packet(packet_content, client_socket)
            elif opcode == 0x03:
                # Add your packet handling logic here
                pass
            # ... other opcodes as in your template ...
            elif opcode == 0x19:
                pass
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")
            self._close_connection(client_socket)
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    server = Server()
    server.start()
    server.run()

    
"""
import socket
import sys
import threading
# import driver


class Server:
    def response_packet(self, packet_content: bytes, client_socket):
        try:
            client_socket.send(packet_content)
        except:
            print(f"Failed to send response to client {client_socket.getpeername()}")
            
    def handle_packet(self, packet_content: bytes, client_socket):
        try:
            opcode = packet_content[4]

            if opcode == 0x01:
                # response_packet(packet_content: bytes, client_socket)
                pass
            elif opcode == 0x03:
                pass
            elif opcode == 0x05:
                pass
            elif opcode == 0x07:
                pass
            elif opcode == 0x09:
                pass
            elif opcode == 0x11:
                pass
            elif opcode == 0x13:
                pass
            elif opcode == 0x15:
                pass
            elif opcode == 0x17:
                pass
            elif opcode == 0x19:
                pass
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")




"""

"""         
class Server:
    def __init__(self, port: int, host: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.clients = []
        
    def start(self):
        print(f"Server started on {self.sock.getsockname()}")
        while True:
            client_socket, address = self.sock.accept()
            self.clients.append(client_socket)
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            
    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.handle_packet(data, client_socket)
            except:
                break
        client_socket.close()
        self.clients.remove(client_socket)

    def response_packet(self, packet_content: str, client_socket):
        try:
            client_socket.send(packet_content.encode())
        except:
            print(f"Failed to send response to client {client_socket.getpeername()}")
            
    def handle_packet(self, packet_content: bytes, client_socket):
        try:
            opcode = packet_content[4]

            if opcode == 0x01:
                pass
            elif opcode == 0x03:
                pass
            elif opcode == 0x05:
                pass
            elif opcode == 0x07:
                pass
            elif opcode == 0x09:
                pass
            elif opcode == 0x11:
                pass
            elif opcode == 0x13:
                pass
            elif opcode == 0x15:
                pass
            elif opcode == 0x17:
                pass
            elif opcode == 0x19:
                pass
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")
    
        # print(f"Received: {packet_content}")
        # Add your packet handling logic here
        # self.send_packet("foo")
        self.response_packet("Response to 0x03", client_socket)
    
            
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python server.py PORT HOST")
        sys.exit(1)
        
    port = int(sys.argv[1])
    host = sys.argv[2]
    
    server = Server(port, host)
    server.start()
"""
