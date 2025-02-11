
# client.py
import socket
from typing import Optional
import time

class Client:
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

if __name__ == "__main__":
    # Example usage showing persistent connection
    client = Client()
    client.connect()
    
    try:
        # Send multiple messages
        for i in range(3):
            packet = f'\x00\x00\x00\x00\x01Message {i}!'.encode()
            response = client.send_request(packet)
            print(f"Received response {i}: {response}")
            time.sleep(1)  # Pause between messages to demonstrate persistence
            
        print("Done sending messages. Connection will remain open until explicit disconnect.")
        # Uncomment the next line to explicitly close the connection:
        # client.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        
