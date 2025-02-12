
# client.py
import socket
from typing import Optional
import time
import hashlib
import json

class Client:
    # GENERAL-FORM SOCKET FN's START
    def __init__(self, host: str, port: int, use_json: bool = False):
        self.host = host
        self.port = port
        self.use_json = use_json
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

    def hash_password(password: str):
        return hashlib.sha256(password.encode()).hexdigest()
        
    def build_packet(self, opcode: int, payload: bytes) -> bytes:
        """
        Builds a packet that consists of:
          - A 4-byte header containing the length of the body (opcode + payload)
          - A 1-byte opcode
          - The payload bytes
        """
        body = bytes([opcode]) + payload
        length_header = len(body).to_bytes(4, byteorder='big')
        return length_header + body

    def build_json_packet(self, data: dict) -> bytes:
        """Build a JSON protocol packet using a length header and JSON body."""
        json_data = json.dumps(data).encode('utf-8')
        length_header = len(json_data).to_bytes(4, byteorder='big')
        return length_header + json_data        

    # GENERAL-FORM SOCKET FN's END

    # OP CODE FUNCTIONS START

    # 0x01: Search Username
    def search_username(self, username: str) -> bool:
        """
        In binary mode:
          Request: 4-byte length, 0x01, 2-byte username length, username (UTF-8)
          Response: 4-byte length, 0x02, 1-byte status code (0x00 means available)
          
        In JSON mode:
          Request: { "opcode": "search_username", "username": <username> }
          Response: { "opcode": "search_username_response", "available": true/false }
        """
        if self.use_json:
            # Build JSON packet
            packet = self.build_json_packet({
                "opcode": "search_username",
                "username": username
            })
            response = self.send_request(packet)
            # Assume the first 4 bytes are the length; the rest is a JSON string.
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            return response_data.get("available", False)
        else:
            # Custom Wire Protocol Packet
            username_bytes = username.encode('utf-8')
            username_length = len(username_bytes)
            packet_body = bytes([0x01]) + username_length.to_bytes(2, byteorder='big') + username_bytes
            packet = len(packet_body).to_bytes(4, byteorder='big') + packet_body
            response = self.send_request(packet)
            if len(response) < 6:
                raise Exception("Incomplete response")
            opcode_resp = response[4]
            if opcode_resp != 0x02:
                raise Exception("Unexpected opcode in search_username")
            status = response[5]
            return status == 0x00

    # 0x03: Create Account
    def create_account(self, username: str, password: str) -> str:
        """
        In binary mode:
          Request: 4-byte length, 0x03, 2-byte username length, username (UTF-8),
                   32-byte hashed password.
          Response: 4-byte total length, 0x04, 32-byte session token.
          
        In JSON mode:
          Request: { "opcode": "create_account",
                     "username": <username>,
                     "hashed_password": <sha256_hex_of_password> }
          Response: { "opcode": "create_account_response",
                      "session_token": <session token (hex)> }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "create_account",
                "username": username,
                "hashed_password": hashlib.sha256(password.encode('utf-8')).hexdigest()
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            return response_data.get("session_token")
        else:
            username_bytes = username.encode('utf-8')
            username_length = len(username_bytes)
            hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
            packet_body = bytes([0x03]) \
                          + username_length.to_bytes(2, byteorder='big') \
                          + username_bytes \
                          + hashed_password
            packet_length = len(packet_body).to_bytes(4, byteorder='big')
            packet = packet_length + packet_body
            response = self.send_request(packet)
            if len(response) < 4 + 1 + 32:
                raise Exception("Incomplete response")
            opcode_resp = response[4]
            if opcode_resp != 0x04:
                raise Exception("Unexpected opcode in create_account")
            token = response[5:37].hex()
            return token

    # 0x05: Log into Account
    def log_into_account(self, username: str, password: str) -> tuple[bool, str, int]:
        """
        In binary mode:
          Request: 4-byte length, 0x05, 2-byte username length, username (UTF-8),
                   32-byte hashed password.
          Response: 4-byte total length, 0x06, 1-byte status code,
                    32-byte session token, 4-byte unread messages count.
                    
        In JSON mode:
          Request: { "opcode": "log_into_account",
                     "username": <username>,
                     "hashed_password": <sha256_hex_of_password> }
          Response: { "opcode": "log_into_account_response",
                      "success": true/false,
                      "session_token": <session token (hex)>,
                      "unread_count": <integer> }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "log_into_account",
                "username": username,
                "hashed_password": hashlib.sha256(password.encode('utf-8')).hexdigest()
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            success = response_data.get("success", False)
            token = response_data.get("session_token", "")
            unread_count = response_data.get("unread_count", 0)
            return success, token, unread_count
        else:
            username_bytes = username.encode('utf-8')
            username_length = len(username_bytes)
            hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
            packet_body = bytes([0x05]) \
                          + username_length.to_bytes(2, byteorder='big') \
                          + username_bytes \
                          + hashed_password
            packet_length = len(packet_body).to_bytes(4, byteorder='big')
            packet = packet_length + packet_body
            response = self.send_request(packet)
            if len(response) < 4 + 1 + 1 + 32 + 4:
                raise Exception("Incomplete response")
            opcode_resp = response[4]
            if opcode_resp != 0x06:
                raise Exception("Unexpected opcode in log_into_account")
            status = response[5]
            success = status == 0x00
            token = response[6:38].hex()
            unread_count = int.from_bytes(response[38:42], byteorder='big')
            return success, token, unread_count

    # 0x07: Log out of Account
    def log_out_of_account(self, user_id: int, session_token: str) -> None:
        """
        In binary mode:
          Request: 4-byte length, 0x07, 2-byte user id, 32-byte session token.
          Response: 4-byte total length, 0x08.
          
        In JSON mode:
          Request: { "opcode": "log_out_of_account",
                     "user_id": <user_id>,
                     "session_token": <session_token> }
          Response: { "opcode": "log_out_of_account_response" }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "log_out_of_account",
                "user_id": user_id,
                "session_token": session_token
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            if response_data.get("opcode") != "log_out_of_account_response":
                raise Exception("Unexpected response in log_out_of_account")
            return
        else:
            packet_body = bytes([0x07]) \
                          + user_id.to_bytes(2, byteorder='big') \
                          + bytes.fromhex(session_token)
            packet_length = len(packet_body).to_bytes(4, byteorder='big')
            packet = packet_length + packet_body
            response = self.send_request(packet)
            if len(response) < 4 + 1:
                raise Exception("Incomplete response")
            opcode_resp = response[4]
            if opcode_resp != 0x08:
                raise Exception("Unexpected opcode in log_out_of_account")

    # 0x09: List Accounts
    def list_accounts(self, user_id: int, session_token: str, wildcard: str) -> list[str]:
        """
        In binary mode:
          Request: 4-byte length, 0x09, 2-byte user id, 32-byte session token,
                   2-byte wildcard length, wildcard (UTF-8).
          Response: 4-byte total length, 0x10, 2-byte account count,
                    then for each account: 2-byte username length, username (UTF-8).
                    
        In JSON mode:
          Request: { "opcode": "list_accounts",
                     "user_id": <user_id>,
                     "session_token": <session_token>,
                     "wildcard": <wildcard> }
          Response: { "opcode": "list_accounts_response",
                      "accounts": [ <username>, ... ] }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "list_accounts",
                "user_id": user_id,
                "session_token": session_token,
                "wildcard": wildcard
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            return response_data.get("accounts", [])
        else:
            wildcard_bytes = wildcard.encode('utf-8')
            wildcard_length = len(wildcard_bytes)
            packet_body = bytes([0x09]) \
                          + user_id.to_bytes(2, byteorder='big') \
                          + bytes.fromhex(session_token) \
                          + wildcard_length.to_bytes(2, byteorder='big') \
                          + wildcard_bytes
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
    def display_conversation(self, user_id: int, session_token: str, conversant_id: int) -> list[tuple[int, str, bool]]:
        """
        In binary mode:
          Request: 4-byte length, 0x11, 2-byte user id, 32-byte session token, 2-byte conversant id.
          Response: 4-byte total length, 0x12, 4-byte message count,
                    then for each message: 4-byte message id, 2-byte message length,
                    1-byte flag (0x01 if sender, else 0x00), message content (UTF-8).
                    
        In JSON mode:
          Request: { "opcode": "display_conversation",
                     "user_id": <user_id>,
                     "session_token": <session_token>,
                     "conversant_id": <conversant_id> }
          Response: { "opcode": "display_conversation_response",
                      "messages": [ 
                          { "message_id": <int>, "content": <str>, "is_sender": <bool> },
                          ... 
                      ] }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "display_conversation",
                "user_id": user_id,
                "session_token": session_token,
                "conversant_id": conversant_id
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            messages = response_data.get("messages", [])
            result = []
            for msg in messages:
                result.append((msg.get("message_id"), msg.get("content"), msg.get("is_sender")))
            return result
        else:
            packet_body = bytes([0x11]) \
                          + user_id.to_bytes(2, byteorder='big') \
                          + bytes.fromhex(session_token) \
                          + conversant_id.to_bytes(2, byteorder='big')
            packet_length = len(packet_body).to_bytes(4, byteorder='big')
            packet = packet_length + packet_body
            response = self.send_request(packet)
            if len(response) < 4 + 1 + 4:
                raise Exception("Incomplete response")
            opcode = response[4]
            if opcode != 0x12:
                raise Exception("Unexpected opcode in display_conversation")
            message_count = int.from_bytes(response[5:9], byteorder='big')
            messages = []
            current_pos = 9
            for _ in range(message_count):
                if len(response) < current_pos + 4 + 2 + 1:
                    raise Exception("Incomplete message data")
                msg_id = int.from_bytes(response[current_pos:current_pos+4], byteorder='big')
                current_pos += 4
                msg_length = int.from_bytes(response[current_pos:current_pos+2], byteorder='big')
                current_pos += 2
                is_sender = response[current_pos] == 0x01
                current_pos += 1
                if len(response) < current_pos + msg_length:
                    raise Exception("Incomplete message content")
                msg_content = response[current_pos:current_pos+msg_length].decode('utf-8')
                current_pos += msg_length
                messages.append((msg_id, msg_content, is_sender))
            return messages

    # 0x13: Send Message
    def send_message(self, user_id: int, session_token: str, recipient_id: int, message: str) -> None:
        """
        In binary mode:
        Request: 4-byte length, 0x13, user ID (2 bytes), session token (32 bytes),
               recipient ID (2 bytes), message length (2 bytes), message (UTF-8)
        Response: 4-byte total length, 0x14
              
        In JSON mode:
        Request: { "opcode": "send_message",
                 "user_id": <user_id>,
                 "session_token": <session_token>,
                 "recipient_id": <recipient_id>,
                 "message": <message> }
        Response: { "opcode": "send_message_response" }
        """
        if self.use_json:
            packet = self.build_json_packet({
                "opcode": "send_message",
                "user_id": user_id,
                "session_token": session_token,
                "recipient_id": recipient_id,
                "message": message
            })
            response = self.send_request(packet)
            json_str = response[4:].decode('utf-8')
            response_data = json.loads(json_str)
            if response_data.get("opcode") != "send_message_response":
                raise Exception("Unexpected opcode in send_message response")
            return
        else:
            token_bytes = bytes.fromhex(session_token)
            if len(token_bytes) != 32:
                raise ValueError("Decoded session token must be 32 bytes")
            
            packet_body = bytes([0x13])
            packet_body += user_id.to_bytes(2, byteorder='big')
            packet_body += token_bytes
            packet_body += recipient_id.to_bytes(2, byteorder='big')
            
            message_bytes = message.encode('utf-8')
            packet_body += len(message_bytes).to_bytes(2, byteorder='big')
            packet_body += message_bytes
            
            packet_length = len(packet_body).to_bytes(4, byteorder='big')
            packet = packet_length + packet_body
            
            response = self.send_request(packet)
            if len(response) < 5:
                raise Exception("Incomplete response for send_message")
            if response[4] != 0x14:
                raise Exception(f"Unexpected opcode in send_message response: {response[4]:#04x}")

    # 0x15: Read Messages
    def read_messages(self, user_id: int, session_token: str, num_messages: int) -> None:
        """
        Opcode 0x15 (Read Messages); expects a Response (0x16).

        Request format:
          - 4-byte total length
          - 0x15
          - user ID (2 bytes)
          - session token (32 bytes, hex -> raw)
          - number of desired messages (4 bytes)
          
        Response format:
          - 4-byte total length
          - 0x16
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")

        packet_body = bytes([0x15])
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += token_bytes
        packet_body += num_messages.to_bytes(4, byteorder='big')

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for read_messages")
        if response[4] != 0x16:
            raise Exception(f"Unexpected opcode in read_messages response: {response[4]:#04x}")

    # 0x17: Delete Message
    def delete_message(self, user_id: int, message_uid: int, session_token: str) -> None:
        """
        Opcode 0x17 (Delete Message); expects a Response (0x18).

        Request format:
          - 4-byte total length
          - 0x17
          - user ID (2 bytes)
          - message UID (4 bytes)
          - session token (32 bytes, hex -> raw)
          
        Response format:
          - 4-byte total length
          - 0x18
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")

        packet_body = bytes([0x17])
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += message_uid.to_bytes(4, byteorder='big')
        packet_body += token_bytes

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for delete_message")
        if response[4] != 0x18:
            raise Exception(f"Unexpected opcode in delete_message response: {response[4]:#04x}")

    # 0x19: Delete Account
    def delete_account(self, user_id: int, session_token: str) -> None:
        """
        Opcode 0x19 (Delete Account); expects a Response (0x20).

        Request format:
          - 4-byte total length
          - 0x19
          - user ID (2 bytes)
          - session token (32 bytes, hex -> raw)
          
        Response format:
          - 4-byte total length
          - 0x20
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")

        packet_body = bytes([0x19])
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += token_bytes

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for delete_account")
        if response[4] != 0x20:
            raise Exception(f"Unexpected opcode in delete_account response: {response[4]:#04x}")

    # 0x21: Get Unread Messages
    def get_unread_messages(self, user_id: int, session_token: str) -> list[tuple[int, int, int]]:
        """
        Opcode 0x21 (Get Unread Messages Request) and expects a Response (0x22).

        Request format:
          - 4-byte total length
          - 0x21
          - user ID (2 bytes)
          - session token (32 bytes, hex string converted to raw bytes)

        Response format:
          - 4-byte total length
          - 0x22
          - number of unread messages (4 bytes)
            For each unread message:
              * message UID (4 bytes)
              * sender ID (2 bytes)
              * receiver ID (2 bytes)
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")

        packet_body = bytearray()
        packet_body.append(0x21)
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += token_bytes

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for get_unread_messages")
        if response[4] != 0x22:
            raise Exception(f"Unexpected opcode in get_unread_messages response: {response[4]:#04x}")

        # Parse the number of unread messages (bytes 5 to 8)
        if len(response) < 9:
            raise Exception("Incomplete response: missing unread messages count")
        num_unread = int.from_bytes(response[5:9], byteorder='big')

        messages = []
        offset = 9
        expected_length = offset + num_unread * 8  # each message entry is 8 bytes
        if len(response) < expected_length:
            raise Exception("Incomplete response: not all unread messages received")
        for _ in range(num_unread):
            msg_uid = int.from_bytes(response[offset:offset+4], byteorder='big')
            sender_id = int.from_bytes(response[offset+4:offset+6], byteorder='big')
            receiver_id = int.from_bytes(response[offset+6:offset+8], byteorder='big')
            messages.append((msg_uid, sender_id, receiver_id))
            offset += 8

        return messages

    # 0x23: Get Message Information
    def get_message_info(self, user_id: int, session_token: str, message_uid: int) -> tuple[bool, int, str]:
        """
        Opcode 0x23 (Get Message Information Request) and expects a Response (0x24).

        Request format:
          - 4-byte total length
          - 0x23
          - user ID (2 bytes)
          - session token (32 bytes, hex -> raw)
          - message UID (4 bytes)

        Response format:
          - 4-byte total length
          - 0x24
          - has been read (1 byte; 0 or 1)
          - sender ID (2 bytes)
          - content length (2 bytes)
          - message content (UTF-8, content length bytes)
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")
        
        packet_body = bytearray()
        packet_body.append(0x23)
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += token_bytes
        packet_body += message_uid.to_bytes(4, byteorder='big')
        
        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for get_message_info")
        if response[4] != 0x24:
            raise Exception(f"Unexpected opcode in get_message_info response: {response[4]:#04x}")

        # Response body: byte 5: has_been_read (1 byte)
        # bytes 6-7: sender ID (2 bytes)
        # bytes 8-9: content length (2 bytes)
        if len(response) < 10:
            raise Exception("Incomplete response for message information")
        has_been_read = bool(response[5])
        sender_id = int.from_bytes(response[6:8], byteorder='big')
        content_length = int.from_bytes(response[8:10], byteorder='big')
        if len(response) < 10 + content_length:
            raise Exception("Incomplete response: message content truncated")
        message_content = response[10:10+content_length].decode('utf-8')
        
        return (has_been_read, sender_id, message_content)

    # 0x25: Get Username by ID
    def get_username_by_id(self, user_id: int) -> str:
        """
        Opcode 0x25 (Get Username by ID Request) and expects a Response (0x26).

        Request format:
          - 4-byte total length
          - 0x25
          - user ID (2 bytes)

        Response format:
          - 4-byte total length
          - 0x26
          - username length (2 bytes)
          - username (UTF-8)
        """
        packet_body = bytearray()
        packet_body.append(0x25)
        packet_body += user_id.to_bytes(2, byteorder='big')

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for get_username_by_id")
        if response[4] != 0x26:
            raise Exception(f"Unexpected opcode in get_username_by_id response: {response[4]:#04x}")

        if len(response) < 7:
            raise Exception("Incomplete response: missing username length")
        username_length = int.from_bytes(response[5:7], byteorder='big')
        if len(response) < 7 + username_length:
            raise Exception("Incomplete response: username data truncated")
        username = response[7:7+username_length].decode('utf-8')
        
        return username

    # 0x27: Mark Message as Read
    def mark_message_as_read(self, user_id: int, session_token: str, message_uid: int) -> None:
        """
        Opcode 0x27 (Mark Message as Read Request) and expects a Response (0x28).

        Request format:
          - 4-byte total length
          - 0x27
          - user ID (2 bytes)
          - session token (32 bytes, hex -> raw)
          - message UID (4 bytes)

        Response format:
          - 4-byte total length
          - 0x28
        """
        token_bytes = bytes.fromhex(session_token)
        if len(token_bytes) != 32:
            raise ValueError("Decoded session token must be 32 bytes")
        
        packet_body = bytearray()
        packet_body.append(0x27)
        packet_body += user_id.to_bytes(2, byteorder='big')
        packet_body += token_bytes
        packet_body += message_uid.to_bytes(4, byteorder='big')

        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
        if len(response) < 5:
            raise Exception("Incomplete response for mark_message_as_read")
        if response[4] != 0x28:
            raise Exception(f"Unexpected opcode in mark_message_as_read response: {response[4]:#04x}")

    # 0x29: Get username by userID
    def get_user_by_username(self, username: str) -> tuple[bool, Optional[int]]:
        """
        Opcode 0x29 (Get User by Username Request) and expects a Response (0x2A).
    
        Request format:
        - 4-byte total length
        - 1-byte opcode (0x29)
        - 2-byte username length
        - username (UTF-8)
        
        Response format:
        - 4-byte total length
        - 1-byte opcode (0x2A)
        - 1-byte status code (0x00 if found, 0x01 if not found)
        - if found: 2-byte user ID
        
        Returns:
        Tuple (found: bool, user_id: int or None)
        """
        username_bytes = username.encode('utf-8')
        username_length = len(username_bytes)
    
        packet_body = bytearray()
        packet_body.append(0x29)
        packet_body += username_length.to_bytes(2, byteorder='big')
        packet_body += username_bytes
        
        packet_length = len(packet_body).to_bytes(4, byteorder='big')
        packet = packet_length + packet_body

        response = self.send_request(packet)
    
        if len(response) < 5:
            raise Exception("Incomplete response for get_user_by_username")
        if response[4] != 0x2A:
            raise Exception(f"Unexpected opcode in get_user_by_username response: {response[4]:#04x}")
    
        status = response[5]
        if status == 0x00:
            if len(response) < 8:
                raise Exception("Incomplete response: missing user ID")
            user_id = int.from_bytes(response[6:8], byteorder='big')
            return True, user_id
        else:
            return False, None
        
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
        
