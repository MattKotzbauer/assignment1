
# client.py
import socket
from typing import Optional
import time
import hashlib

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
        
    # 0x03: Create Account
    def create_account(self, username: str, password: str) -> str: 
        """
        Opcode 0x03 (Create Account Request) and expect a Response (0x04):
        Request format:
            4-byte length of following body,
            0x03,
            2-byte username length,
            username (UTF-8),
            32-byte hashed password
        Response format:
            4-byte total length,
            0x04,
            32-byte session token
        """
        username_bytes = username.encode('utf-8')
        username_length = len(username_bytes)
        hashed_password = hashlib.sha256(password.encode('utf-8')).digest() 
        
        packet_body = bytes([0x03])
        packet_body += username_length.to_bytes(2, byteorder='big')
        packet_body += username_bytes
        packet_body += hashed_password
        packet_length = len(packet_body).to_bytes(4, byteorder='big')

        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 4 + 1 + 32:
            raise Exception("incomplete response")
        
        opcode_resp = response[4]
        if opcode_resp != 0x04:
            raise Exception("Unexpected opcode in create_account")

        token = response[5:37].hex()
        return token

    # 0x05: Log into Account
    def log_into_account(self, username: str, password: str) -> tuple[bool, str, int]:
        """
        Opcode 0x05 (Login Account Request) and expect a Response (0x06):
        Request format:
            4-byte length of following body,
            0x05,
            2-byte username length,
            username (UTF-8),
            32-byte hashed password
        Response format:
            4-byte total length,
            0x06,
            1-byte status code
                0x00 => success
                0x01 => invalid credentials
            32-byte session token,
            4-byte unread messages count
        """
        username_bytes = username.encode('utf-8')
        username_length = len(username_bytes)
        hashed_password = hashlib.sha256(password.encode('utf-8')).digest()

        packet_body = bytes([0x05])
        packet_body += username_length.to_bytes(2, byteorder='big')
        packet_body += username_bytes
        packet_body += hashed_password
        packet_length = len(packet_body).to_bytes(4, byteorder='big')

        packet = packet_length + packet_body
        response = self.send_request(packet)
        
        if len(response) < 4 + 1 + 1 + 32 + 4:
            raise Exception("Incomplete response")

        opcode_resp = response[4]
        if opcode_resp != 0x06:
            raise Exception("Unexpected opcode in login_account")

        status = response[5]
        success = status == 0x00
        token = response[6:38].hex()
        unread_count = int.from_bytes(response[38:42], byteorder='big')

        return success, token, unread_count
        
    # 0x07: Log out of Account
    def log_out_of_account(self, user_id: int, session_token: str) -> None:
        """
        Opcode 0x07 (Log Out Request) and expect a Response (0x08):
        Request format:
            4-byte length of following body,
            0x07,
            2-byte user id,
            32-byte session token
        Response format:
            4-byte total length,
            0x08
        """
        packet_body = bytes([0x07])
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += bytes.fromhex(session_token)
        packet_length = len(packet_body).to_bytes(4, byteorder='big')

        packet =  packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 4 + 1:
            raise Exception("Incomplete response")

        opcode_resp = response[4]
        if opcode_resp != 0x08:
            raise Exception("Unexpected opcode in log_out_account")
    
    # 0x09: List Accounts
    def list_accounts(self, user_id: int, session_token: str, wildcard: str) -> list[str]:
        """
        Opcode 0x09 (List Accounts Request) and expect a Response (0x10):
        Request format:
            4-byte length of following body,
            0x09,
            2-byte user id,
            32-byte session token,
            2-byte wildcard length,
            wildcard string (UTF-8)
        Response format:
            4-byte total length,
            0x10,
            2-byte count of accounts,
            for each account:
                2-byte username length,
                username (UTF-8)
        """
        wildcard_bytes = wildcard.encode('utf-8')
        wildcard_length = len(wildcard_bytes)

        packet_body = bytes([0x09])
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += bytes.fromhex(session_token)
        packet_body += wildcard_length.to_bytes(2, byteorder='big')
        packet_body += wildcard_bytes
        packet_length = len(packet_body).to_bytes(4, byteorder='big')

        packet = packet_length + packet_body
        
        response = self.send_request(packet)
        if len(response) < 4 + 1 + 2:
            raise Exception("Incomplete response")

        opcode_resp = response[4]
        if opcode_resp != 0x10:
            raise Exception("Unexpected opcode in list_accounts")

        account_count = int.from_bytes(response[5:7], byteorder='big')
        usernames = []
        pos = 7
        
        for _ in range(account_count):
            if len(response) < pos + 2:
                raise Exception("Incomplete response")
            username_length = int.from_bytes(response[pos:pos+2], byteorder='big')
            pos += 2
            
            if len(response) < pos + username_length:
                raise Exception("Incomplete response")
            username = response[pos:pos+username_length].decode('utf-8')
            pos += username_length
            usernames.append(username)

        return usernames
            
    # 0x11: Display Conversation
    
    
    # 0x13: Send Message
    
    
    # 0x15: Read Messages
    
    
    # 0x17: Delete Message
    
    
    # 0x19: Delete Account
    
    
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
        
