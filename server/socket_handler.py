# server.py
import socket
import selectors
import types
from typing import Dict, Optional
import driver
from core_entities import Message, User

class Server:
    # GENERAL-FORM SOCKET FN's START
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
    # GENERAL-FORM SOCKET FN's END
      
    # PACKET HANDLER CONTROL FLOW START
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

            # packet_length: denotes length of remaining packet content
            packet_length = int.from_bytes(packet_content[0:4], byteorder='big')
            # opcode: denotes type of request
            opcode = packet_content[4]

            full_response = None
            
            if opcode == 0x01: 
                full_response = self.search_username(packet_content)
            elif opcode == 0x03:
                full_response = self.create_account(packet_content)
            elif opcode == 0x05:
                full_response = self.log_into_account(packet_content)
            elif opcode == 0x07:
                full_response = self.log_out_of_account(packet_content)
            elif opcode == 0x09:
                full_response = self.list_account(packet_content)
            elif opcode == 0x11:
                full_response = self.display_conversation(packet_content)
            elif opcode == 0x13:
                full_response = self.send_message(packet_content)
            elif opcode == 0x15:
                full_response = self.read_messages(packet_content)
            elif opcode == 0x17:
                full_response = self.delete_message(packet_content)
            elif opcode == 0x19:
                full_response = self.delete_account(packet_content)

            if full_response: 
                """U6: Send response packet back to client"""
                self.response_packet(full_response, client_socket)
            
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    # PACKET HANDLER CONTROL FLOW END

    # OP CODE FUNCTIONS START
    
    # 0x01: Search Username
    def search_username(self, packet_content: bytes) -> bytes:
        # Request format (Enter username):
        #   1. Length (4 bytes) of remaining packet body
        #   2. Opcode 0x01 (1 byte) - enter username request
        #   3. Username length (2 bytes)
        #   4. Username (variable length, UTF-8 encoded)
        """
        U3. Cast wire protocol packet into API function inputs)
            * (note that our op code dictates which function we send the packet bytes into, which dictates
                   the fields that we process as input)
        """
        username_length = int.from_bytes(packet_content[5:7], byteorder='big')
        username = packet_content[7:7+username_length].decode('utf-8')
        """U4: Call server-side API function using input values"""
        user_exists = driver.user_trie.trie.get(username) is not None
        status = 0x01 if user_exists else 0x00
        print(f"Username '{username}' exists: {user_exists}. Sending status code {status:#04x}.")
        # Response format:
        #   1. Length (4 bytes) of remaining packet body (here: opcode + status = 1 + 1 = 2 bytes)
        #   2. Opcode 0x02 (1 byte)
        #   3. Status code (1 byte)
        #      - 0x00: username is available (client should send 0x03 register request)
        #      - 0x01: username is taken (client should send 0x05 login request)
        """U5: Cast API function output values into wire protocol packet"""
        response_body = bytes([0x02, status])
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        return full_response
            
    # 0x03: Create Account
    def create_account(self, packet_content: bytes) -> bytes:
        # Request format (Create account):
        #   1. Length (4 bytes) of remaining packet body
        #   2. Opcode 0x03 (1 byte) - create account request
        #   3. Username length (2 bytes)
        #   4. Username (variable length, UTF-8 encoded)
        #   5. Hashed password (32 bytes)
        username_length = int.from_bytes(packet_content[5:7], byteorder='big')
        username = packet_content[7:7+username_length].decode('utf-8')
        hashed_password_bytes = packet_content[7+username_length:7+username_length+32]
        hashed_password_hex = hashed_password_bytes.hex()

        token = driver.create_account(username, hashed_password_hex)
        token_bytes = bytes.fromhex(token)

        # Response format:
        #   1. Length (4 bytes) of remaining packet body (here: opcode + token = 1 + 32 = 33 bytes)
        #   2. Opcode 0x04 (1 byte)
        #   3. Session token (32 bytes)
        response_body = bytes([0x04]) + token_bytes
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        return full_response
        
    # 0x05: Log into Account
    def log_into_account(self, packet_content: bytes) -> bytes:
        # Request format (Log into account):
        #   1. Length (4 bytes) of remaining packet body
        #   2. Opcode 0x05 (1 byte) - login request
        #   3. Username length (2 bytes)
        #   4. Username (variable length, UTF-8 encoded)
        #   5. Hashed password (32 bytes)
        username_length = int.from_bytes(packet_content[5:7], byteorder='big')
        username = packet_content[7:7+username_length].decode('utf-8')
        hashed_password_bytes = packet_content[7+username_length:7+username_length+32] 
        hashed_password_hex = hashed_password_bytes.hex()

        user = driver.user_trie.trie.get(username)
        if user is not None and driver.check_password(username, hashed_password_hex):
            status = 0x00
            token = driver.generate_session_token(user.userID)
            token_bytes = bytes.fromhex(token)
            unread_count = len(user.unread_messages)
        else:
            status = 0x01
            token_bytes = bytes(32)
            unread_count = 0

        # Response format:
        #   1. Length (4 bytes) of remaining packet body (here: opcode + status + token + unread = 1 + 1 + 16 + 4 = 22 bytes)
        #   2. Opcode 0x06 (1 byte)
        #   3. Status code (1 byte)
        #      - 0x00: success
        #      - 0x01: invalid credentials
        #   4. Session token (32 bytes)
        #   5. Unread messages count (4 bytes)
        response_body = bytes([0x06, status]) + token_bytes + unread_count.to_bytes(4, byteorder='big')
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        return full_response
        
    # 0x07: Log out of Account
    def log_out_of_account(self, packet_content: bytes) -> bytes: 
        # Request format (Log out account):
        #   1. Length (4 bytes) of remaining packet body
        #   2. Opcode 0x07 (1 byte) - logout request
        #   3. User ID (2 bytes)
        #   4. Session token (32 bytes)
        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        provided_token = packet_content[7:7+32]

        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token:
            stored_token_bytes = bytes.fromhex(stored_token)
            if stored_token_bytes == provided_token:
                del driver.session_tokens.tokens[user_id]
                
        # Response format:
        #   1. Length (4 bytes) of remaining packet body (here: opcode = 1 byte)
        #   2. Opcode 0x08 (1 byte)
        response_body = bytes([0x08])
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        print(full_response)
        return full_response

    # 0x09: List Accounts
    def list_account(self, packet_content: bytes) -> bytes:
        # Correct parsing:
        # Byte 0-3: Length
        # Byte 4: Opcode (0x09)
        # Bytes 5-6: User ID (2 bytes)
        # Bytes 7-38: Session token (32 bytes)
        # Bytes 39-40: Wildcard length (2 bytes)
        # Bytes 41+: Wildcard string (UTF-8)

        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        provided_token = packet_content[7:7+32]  # Correct offset for the token
        wildcard_length = int.from_bytes(packet_content[7+32:7+32+2], byteorder='big')
        wildcard = packet_content[7+32+2:7+32+2+wildcard_length].decode('utf-8')
        
        stored_token = driver.session_tokens.tokens.get(user_id)
        # If authentication were enabled, we would check:
        authenticated = stored_token and bytes.fromhex(stored_token) == provided_token
        matching_accounts = driver.list_accounts(wildcard) if authenticated else []
        # matching_accounts = driver.list_accounts(wildcard)

        # Response format:
        #   1. Length (4 bytes) of remaining packet body
        #   2. Opcode 0x10 (1 byte)
        #   3. Number of matching accounts (2 bytes)
        #   4. For each account:
        #      - Username length (2 bytes)
        #      - Username (variable length, UTF-8 encoded)
        
        # Response construction remains unchanged...
        count = len(matching_accounts)
        response_body = bytes([0x10]) + count.to_bytes(2, byteorder='big')
        
        for username in matching_accounts:
            username_bytes = username.encode('utf-8')
            uname_length = len(username_bytes)
            response_body += uname_length.to_bytes(2, byteorder='big') + username_bytes
            
            response_length = len(response_body).to_bytes(4, byteorder='big')
            full_response = response_length + response_body
            return full_response
    
    # 0x11: Display Conversation
    def display_conversation(self, packet_content: bytes) -> bytes:
        pass
    
    # 0x13: Send Message
    def send_message(self, packet_content: bytes) -> bytes:
        pass
    
    # 0x15: Read Messages
    def read_messages(self, packet_content: bytes) -> bytes:
        pass
    
    # 0x17: Delete Message
    def delete_message(self, packet_content: bytes) -> bytes:
        pass
    
    # 0x19: Delete Account
    def delete_account(self, packet_content: bytes) -> bytes:
        pass
    
    # OP CODE FUNCTIONS END
       
    

if __name__ == "__main__":
    server = Server()
    server.start()
    server.run()
