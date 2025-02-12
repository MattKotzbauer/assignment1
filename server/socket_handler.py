# server.py
import socket
import selectors
import types
import traceback
import driver
import json
import sys
from typing import Dict, Optional
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

            full_response = None

            if packet_content[4:5] == b'{':
                # JSON Mode
                try:
                    # Decode the JSON string (everything after the 4-byte header)
                    json_str = packet_content[4:].decode('utf-8')
                    request = json.loads(json_str)
            
                    # Dispatch based on the "opcode" field in the JSON object.
                    opcode = request.get("opcode")
                    if opcode == "search_username":
                        response_data = self.search_username_json(request)
                        # Convert the response back to JSON and prepend the length header.
                    elif opcode == "foo":
                        pass
                        
                    response_json = json.dumps(response_data).encode('utf-8')
                    response_packet = len(response_json).to_bytes(4, byteorder='big') + response_json
                    self.response_packet(response_packet, client_socket)

                except Exception as e:
                    print(f"Error processing JSON packet: {e}")
            else:
                # Opcode: denotes type of request
                opcode = packet_content[4]
                # Custom Wire Protocol Mode: interpret op_code
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
                elif opcode == 0x21:
                    full_response = self.get_unread_messages(packet_content)
                elif opcode == 0x23:
                    full_response = self.get_message_info(packet_content)
                elif opcode == 0x25:
                    full_response = self.get_username_by_id(packet_content)
                elif opcode == 0x27:
                    full_response = self.mark_message_as_read(packet_content)
                elif opcode == 0x29:
                    full_response = self.get_user_by_username(packet_content)
                
            if full_response: 
                """U6: Send response packet back to client"""
                self.response_packet(full_response, client_socket)
            
        except (ConnectionError, socket.error) as e:
            print(f"Connection error: {e}")
        except Exception as e:
            print(f"Error processing packet: {e}")
            traceback.print_exc()

    # PACKET HANDLER CONTROL FLOW END

    # CUSTOM PROTOCOL JSON-BASED FUNCTIONS START
    def search_username_json(self, request: dict) -> dict:
        username = request.get("username", "")
        user_exists = driver.user_trie.trie.get(username) is not None
        available = not user_exists
        print(f"[JSON] Username '{username}' exists: {user_exists}. Responding with available={available}")
        return {
            "opcode": "search_username_response",
            "available": available
    }
    
    # CUSTOM PROTOCOL OP CODE FUNCTIONS START
    
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
        # Request format: 
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
        """
        Request format:
            4-byte length of following body,
            0x11,
            2-byte user id,
            32-byte session token,
            2-byte conversant user id
        """
        if len(packet_content) < 4 + 1 + 2 + 32 + 2:
            print("Display conversation request too short.")
            return b""

        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        session_token = packet_content[7:7+32]
        conversant_id = int.from_bytes(packet_content[7+32:7+32+2], byteorder='big')

        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token is None or bytes.fromhex(stored_token) != session_token:
            print("Invalid session token for display conversation.")
            messages = []
        else:
            # Conversations are stored using a sorted tuple as key
            key = tuple(sorted([user_id, conversant_id]))
            messages = driver.conversations.conversations.get(key, [])
            
        """
        Response format:
            4-byte total length,
            0x12,
            4-byte count of messages,
            For each message:
                4-byte message uid
                2-byte message length
                1-byte flag (0x00 if user is recipient, 0x01 if user is sender)
                message content (UTF-8 string)
        """   
        response_body = bytes([0x12])
        message_count = len(messages)
        response_body += message_count.to_bytes(4, byteorder='big')
        
        for msg in messages:
            uid_bytes = msg.uid.to_bytes(4, byteorder='big')
            content_bytes = msg.contents.encode('utf-8')
            content_length_bytes = len(content_bytes).to_bytes(2, byteorder='big')
            
            # Determine flag: 0x01 if requesting user is sender, else 0x00
            flag = 0x01 if msg.sender_id == user_id else 0x00
            if flag == 0x01 or msg.has_been_read: 
                response_body += uid_bytes + content_length_bytes + bytes([flag]) + content_bytes


        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        
        return full_response

    # 0x13: Send Message
    def send_message(self, packet_content: bytes) -> bytes:
        """
        Request format:
            4-byte total length,
            0x13,
            user ID (2 bytes),
            session token (32 bytes),
            recipient ID (2 bytes),
            message length (2 bytes),
            message content
        """
        if len(packet_content) < 4 + 1 + 2 + 32 + 2 + 2:
            print("Send message request too short.")
            return b""
        
        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        session_token = packet_content[7:7+32]
        recipient_id = int.from_bytes(packet_content[7+32:7+32+2], byteorder='big')
        msg_length = int.from_bytes(packet_content[7+32+2:7+32+2+2], byteorder='big')
        message = packet_content[7+32+2+2:7+32+2+2+msg_length].decode('utf-8')
        
        # Validate token and send message
        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token is None or bytes.fromhex(stored_token) != session_token:
            print("Invalid session token for send message.")
        else:
            driver.send_message(user_id, recipient_id, message)
        """
        Response format:
            4-byte length,
            0x14,
            user ID (2 bytes),
            session token (32 bytes)
        """
            
        response_body = bytes([0x14])
        return len(response_body).to_bytes(4, byteorder='big') + response_body

    # 0x15: Read Messages
    def read_messages(self, packet_content: bytes) -> bytes:
        # Request (0x15):
        #   4-byte total length, 0x15, user ID (2 bytes), session token (32 bytes),
        #   number of desired messages (4 bytes)
        if len(packet_content) < 4 + 1 + 2 + 32 + 4:
            print("Read messages request too short.")
            return b""
        
        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        session_token = packet_content[7:7+32]
        desired_num = int.from_bytes(packet_content[7+32:7+32+4], byteorder='big')
        
        # Validate session token.
        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token is None or bytes.fromhex(stored_token) != session_token:
            print("Invalid session token for read messages.")
        else:
            driver.read_messages(user_id, desired_num)
            
            # Response (0x16): 4-byte length, 0x16 (no additional payload)
            response_body = bytes([0x16])
            response_length = len(response_body).to_bytes(4, byteorder='big')
            full_response = response_length + response_body
            return full_response
        
    # 0x17: Delete Message
    def delete_message(self, packet_content: bytes) -> bytes:
        # Request (0x17):
        #   4-byte total length, 0x17, user ID (2 bytes), message UID (4 bytes),
        #   session token (32 bytes)
        if len(packet_content) < 4 + 1 + 2 + 4 + 32:
            print("Delete message request too short.")
            return b""
        
        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        message_uid = int.from_bytes(packet_content[7:7+4], byteorder='big')
        session_token = packet_content[7+4:7+4+32]
        
        # Validate session token.
        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token is None or bytes.fromhex(stored_token) != session_token:
            print("Invalid session token for delete message.")
        else:
            driver.delete_message(message_uid)
            
        # Response (0x18): 4-byte length, 0x18 (no additional payload)
        response_body = bytes([0x18])
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        return full_response

    # 0x19: Delete Account
    def delete_account(self, packet_content: bytes) -> bytes:
        # Request (0x19):
        #   4-byte total length, 0x19, user ID (2 bytes), session token (32 bytes)
        if len(packet_content) < 4 + 1 + 2 + 32:
            print("Delete account request too short.")
            return b""
        
        user_id = int.from_bytes(packet_content[5:7], byteorder='big')
        session_token = packet_content[7:7+32]
        
        # Validate session token.
        stored_token = driver.session_tokens.tokens.get(user_id)
        if stored_token is None or bytes.fromhex(stored_token) != session_token:
            print("Invalid session token for delete account.")
        else:
            driver.delete_account(user_id)
            
        # Response (0x20): 4-byte length, 0x20 (no additional payload)
        response_body = bytes([0x20])
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        return full_response

    # 0x21: Get user's unread messages
    # Request format:
    #   4-byte length, 0x21, 2-byte user ID, 32-byte session token
    # Response format:
    #   4-byte length, 0x22, 4-byte number of unread messages,
    #   then for each message: 4-byte message UID, 2-byte sender ID, 2-byte receiver ID
    def get_unread_messages(self, packet_content: bytes) -> bytes:
        try:
            # Parse user ID (bytes 5-6) and session token (bytes 7-38)
            user_id = int.from_bytes(packet_content[5:7], byteorder='big')
            session_token_bytes = packet_content[7:39]  # 32 bytes
            provided_token = session_token_bytes.hex()  # convert to hex string for comparison

            # Validate session token (if not valid, log error and return zero messages)
            if user_id not in driver.session_tokens.tokens or driver.session_tokens.tokens[user_id] != provided_token:
                print(f"[get_unread_messages] Invalid session token for user {user_id}")
                unread_list = []
            else:
                user = driver.user_base.users.get(user_id)
                if not user:
                    print(f"[get_unread_messages] User {user_id} not found.")
                    unread_list = []
                else:
                    # Do not clear the unread queue; just copy the list of unread message UIDs.
                    unread_list = list(user.unread_messages)

            num_unread = len(unread_list)
            # Build response payload
            response_body = bytearray()
            response_body.append(0x22)  # opcode for "Get Unread Messages Response"
            response_body += num_unread.to_bytes(4, byteorder='big')
            # For each unread message, pack: UID (4 bytes), sender ID (2 bytes), receiver ID (2 bytes)
            for msg_uid in unread_list:
                msg = driver.message_base.messages.get(msg_uid)
                if msg:
                    response_body += msg.uid.to_bytes(4, byteorder='big')
                    response_body += msg.sender_id.to_bytes(2, byteorder='big')
                    response_body += msg.receiver_id.to_bytes(2, byteorder='big')
            # Prepend 4-byte length header
            length_header = len(response_body).to_bytes(4, byteorder='big')
            return length_header + response_body

        except Exception as e:
            print(f"[get_unread_messages] Exception: {e}")
            # In a real system you might want to return an error response.
            return b""

    # 0x23: Get message information
    # Request format:
    #   4-byte length, 0x23, 2-byte user ID, 32-byte session token, 4-byte message UID
    # Response format:
    #   4-byte length, 0x24, 1-byte "has been read" flag,
    #   2-byte sender ID, 2-byte content length, and message content (UTF-8)
    def get_message_info(self, packet_content: bytes) -> bytes:
        try:
            # Parse fields from the packet
            user_id = int.from_bytes(packet_content[5:7], byteorder='big')
            session_token_bytes = packet_content[7:39]  # 32 bytes
            provided_token = session_token_bytes.hex()
            message_uid = int.from_bytes(packet_content[39:43], byteorder='big')

            # Validate session token
            if user_id not in driver.session_tokens.tokens or driver.session_tokens.tokens[user_id] != provided_token:
                print(f"[get_message_info] Invalid session token for user {user_id}")
                # Set default values if validation fails
                has_been_read = 0
                sender_id = 0
                content_bytes = b""
            else:
                msg = driver.message_base.messages.get(message_uid)
                if not msg:
                    print(f"[get_message_info] Message {message_uid} not found.")
                    has_been_read = 0
                    sender_id = 0
                    content_bytes = b""
                else:
                    # Optionally, verify that the requesting user is authorized (sender or receiver)
                    if user_id not in (msg.sender_id, msg.receiver_id):
                        print(f"[get_message_info] User {user_id} not authorized for message {message_uid}")
                        has_been_read = 0
                        sender_id = 0
                        content_bytes = b""
                    else:
                        has_been_read = 1 if msg.has_been_read else 0
                        sender_id = msg.sender_id
                        content_bytes = msg.contents.encode('utf-8')

            content_length = len(content_bytes)
            response_body = bytearray()
            response_body.append(0x24)  # opcode for "Get Message Info Response"
            response_body.append(has_been_read)
            response_body += sender_id.to_bytes(2, byteorder='big')
            response_body += content_length.to_bytes(2, byteorder='big')
            response_body += content_bytes
            length_header = len(response_body).to_bytes(4, byteorder='big')
            return length_header + response_body

        except Exception as e:
            print(f"[get_message_info] Exception: {e}")
            return b""

    # 0x25: Get username by ID
    # Request format:
    #   4-byte length, 0x25, 2-byte user ID
    # Response format:
    #   4-byte length, 0x26, 2-byte username length, then username (UTF-8)
    def get_username_by_id(self, packet_content: bytes) -> bytes:
        try:
            # Parse the user ID (bytes 5-6)
            user_id = int.from_bytes(packet_content[5:7], byteorder='big')
            user = driver.user_base.users.get(user_id)
            if not user:
                print(f"[get_username_by_id] User {user_id} not found.")
                username_bytes = b""
            else:
                username_bytes = user.username.encode('utf-8')
            username_length = len(username_bytes)
            response_body = bytearray()
            response_body.append(0x26)  # opcode for "Get Username by ID Response"
            response_body += username_length.to_bytes(2, byteorder='big')
            response_body += username_bytes
            length_header = len(response_body).to_bytes(4, byteorder='big')
            return length_header + response_body

        except Exception as e:
            print(f"[get_username_by_id] Exception: {e}")
            return b""

    # 0x27: Mark message as read
    # Request format:
    #   4-byte length, 0x27, 2-byte user ID, 32-byte session token, 4-byte message UID
    # Response format:
    #   4-byte length, 0x28 (no additional payload)
    def mark_message_as_read(self, packet_content: bytes) -> bytes:
        try:
            # Parse the request: user ID, session token, and message UID
            user_id = int.from_bytes(packet_content[5:7], byteorder='big')
            session_token_bytes = packet_content[7:39]
            provided_token = session_token_bytes.hex()
            message_uid = int.from_bytes(packet_content[39:43], byteorder='big')

            # Validate session token
            if user_id not in driver.session_tokens.tokens or driver.session_tokens.tokens[user_id] != provided_token:
                print(f"[mark_message_as_read] Invalid session token for user {user_id}")
            else:
                user = driver.user_base.users.get(user_id)
                if user:
                    # Mark the message as read by removing it from the unread queue (if present)
                    user.mark_message_read(message_uid)
                    # Also update the message object if it exists
                    msg = driver.message_base.messages.get(message_uid)
                    if msg:
                        msg.has_been_read = True

            # Build a minimal response with opcode 0x28
            response_body = bytearray()
            response_body.append(0x28)  # opcode for "Mark Message as Read Response"
            length_header = len(response_body).to_bytes(4, byteorder='big')
            return length_header + response_body

        except Exception as e:
            print(f"[mark_message_as_read] Exception: {e}")
            return b""

    # 0x29: Get user by username
    def get_user_by_username(self, packet_content: bytes) -> bytes:
        """
        Opcode 0x29: Get User by Username Request.
        
        Request format:
        - 4-byte total length
        - 1-byte opcode (0x29)
        - 2-byte username length
        - username (UTF-8)
        
        Response format:
        - 4-byte total length
        - 1-byte opcode (0x2A)
        - 1-byte status code (0x00: found, 0x01: not found)
        - if found: 2-byte user ID
        """
        try:
            # Ensure packet is long enough to contain the username length field.
            if len(packet_content) < 7:
                raise ValueError("Packet too short for get_user_by_username")
            
            # Extract username length and username.
            username_length = int.from_bytes(packet_content[5:7], byteorder='big')
            username = packet_content[7:7+username_length].decode('utf-8')
            print(f"[get_user_by_username] Request for username: {username}")
            
            # Look up the user in the user trie.
            user = driver.user_trie.trie.get(username)
            response_body = bytearray()
            response_body.append(0x2A)  # Response opcode
            
            if user:
                # User found.
                response_body.append(0x00)  # Status: success
                response_body += user.userID.to_bytes(2, byteorder='big')
                print(f"[get_user_by_username] Found user ID: {user.userID}")
            else:
                # User not found.
                response_body.append(0x01)  # Status: not found
                print(f"[get_user_by_username] Username '{username}' not found.")
                
                # Prepend length header.
                response_length = len(response_body).to_bytes(4, byteorder='big')
                return response_length + response_body
            
        except Exception as e:
            print(f"[get_user_by_username] Exception: {e}")
            # On error, return a response with not found status.
            response_body = bytearray([0x2A, 0x01])
            response_length = len(response_body).to_bytes(4, byteorder='big')
            return response_length + response_body

        
    # OP CODE FUNCTIONS END
       
    

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 65432
    
    args = sys.argv[1:]
    if len(args) >= 1:
        host = args[0]
    if len(args) >= 2:
        port = int(args[1])
    
    server = Server(host = host, port = port)
    server.start()
    server.run()
