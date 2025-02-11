
# client.py
import socket
from typing import Optional

class Client:
    def __init__(self, host: str = "127.0.0.1", port: int = 65432):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self):
        """Establish connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close the connection to the server."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_request(self, request_content: bytes) -> bytes:
        """Send a request to the server and return the response."""
        if not self.sock:
            if not self.connect():
                raise ConnectionError("Not connected to server")

        try:
            self.sock.sendall(request_content)
            # Wait for response (assuming fixed-size responses; adjust buffer size as needed)
            response = self.sock.recv(1024)
            return response
        except Exception as e:
            print(f"Error in send_request: {e}")
            self.disconnect()
            raise

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

if __name__ == "__main__":
    # Example usage
    with Client() as client:
        # Example: Send a packet with opcode 0x01
        packet = b'\x00\x00\x00\x00\x01Hello, server!'
        try:
            response = client.send_request(packet)
            print(f"Received response: {response}")
        except Exception as e:
            print(f"Error: {e}")






"""
import socket
import sys
import threading
import struct
# import driver


class Client:
    def send_request(self, request_content: bytes) -> bytes:
        # (return value is content of server response)


class Client:
    def __init__(self, port: int, host: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        
    def start(self):
        print(f"Connected to server at {self.sock.getpeername()}")
        receive_thread = threading.Thread(target=self.receive_packets)
        receive_thread.start()
        
        while True:
            try:
                message = input()
                self.send_packet(message)
            except KeyboardInterrupt:
                break
        
        self.sock.close()
        
    def receive_packets(self):
        while True:
            try:
                data = self.sock.recv(1024)
                if not data:
                    break
                self.handle_packet(data)
            except:
                break
        self.sock.close()
        
    def handle_packet(self, packet_content: str):
        print(f"Received: {packet_content}")
        # Add your packet handling logic here
        
    def send_packet(self, packet_content: str):
        try:
            self.sock.send(packet_content.encode())
        except:
            print("Failed to send packet")
            self.sock.close()

            
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py PORT HOST")
        sys.exit(1)
        
    port = int(sys.argv[1])
    host = sys.argv[2]
    
    client = Client(port, host)
    client.start()

    # GUI LISTENING FN'S
    
    # packet = client_enter_username("test")
    # print(packet.hex())    

"""    
