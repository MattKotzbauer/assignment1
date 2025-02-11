
# client.py
import socket
from typing import Optional
import time

class Client:
    # GENERAL-FORM SOCKET FN's START
    def __init__(self, host: str = "127.0.0.1", port: int = 65432):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self._connected = False

    def connect(self):
        """Establish connection to the server."""
        if self._connected:
            return True
            
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self._connected = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            self._connected = False
            return False

    def disconnect(self):
        """Explicitly disconnect from the server."""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.sock.close()
            self.sock = None
        self._connected = False

    def send_request(self, request_content: bytes) -> bytes:
        """Send a request to the server and return the response."""
        if not self._connected:
            if not self.connect():
                raise ConnectionError("Not connected to server")

        try:
            self.sock.sendall(request_content)
            response = self.sock.recv(1024)
            return response
        except Exception as e:
            print(f"Error in send_request: {e}")
            self.disconnect()
            raise

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    # GENERAL-FORM SOCKET FN's END

    # OP CODE FUNCTIONS START

    # 0x01: Search Username
    def search_username(self, username: str) -> bool:
        """
        Opcode 0x01 (Enter Username Request) and expect a Response (0x02):
          Request format:
            4-byte length of following body,
            0x01,
            2-byte username length,
            username (UTF-8)
          Response format:
            4-byte total length,
            0x02,
            1-byte status code
              0x00 => name untaken (client should send a 0x03 request)
              0x01 => name taken (client should send a 0x05 request)
        """
        # U1: Cast input into wire protocol packet
        username_bytes = username.encode('utf-8')
        username_length = len(username_bytes)

        packet_body = bytes([0x01])
        packet_body += username_length.to_bytes(2, byteorder='big')
        packet_body += username_bytes

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        
        packet = packet_length + packet_body
        # payload = username_length.to_bytes(2, byteorder='big') + username_bytes
        # U2: Send request packet to server
        response = self.send_request(packet)
        if len(response) < 4 + 1 + 1:
            raise Exception("Incomplete response")
        
        opcode_resp = response[4]
        if opcode_resp != 0x02:
            raise Exception("Unexpected opcode in search_username")

        # U7: Cast packet from server into function output type
        status = response[5]
        return status == 0x00
        

    # 0x03: 

    # OP CODE FUNCTIONS END

        
if __name__ == "__main__":
    # Example usage showing persistent connection
    client = Client()
    client.connect()
    
    try:
        alice_available = client.search_username("alice")
        print(f"Username 'alice' available? {alice_available}")
        
        # Send multiple messages
        # for i in range(3):
            # packet = f'\x00\x00\x00\x00\x01Message {i}!'.encode()
            # response = client.send_request(packet)
            # print(f"Received response {i}: {response}")
            # time.sleep(1)  # Pause between messages to demonstrate persistence
            
        # print("Done sending messages. Connection will remain open until explicit disconnect.")
        # Uncomment the next line to explicitly close the connection:
        # client.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        
