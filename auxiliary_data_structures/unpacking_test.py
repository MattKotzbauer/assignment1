from dataclasses import dataclass
from typing import Optional, List
import struct
import hashlib

class WireProtocol:
    @staticmethod
    def pack_string(s: str) -> bytes:
        return s.encode('utf-8')
    
    @staticmethod
    def unpack_string(b: bytes) -> str:
        return b.decode('utf-8')
    
    @dataclass
    class CheckUsername:
        @staticmethod
        def pack(username: str) -> bytes:
            username_bytes = WireProtocol.pack_string(username)
            return struct.pack(
                f'>IbH{len(username_bytes)}s',
                7 + len(username_bytes),  # length
                0x01,                     # request type
                len(username_bytes),      # username length
                username_bytes           # username
            )
        
        @staticmethod
        def unpack(data: bytes) -> tuple[str]:
            length = struct.unpack('>I', data[:4])[0]
            username_len = struct.unpack('>H', data[5:7])[0]
            username = WireProtocol.unpack_string(data[7:7+username_len])
            return (username,)

    @dataclass
    class CreateAccount:
        @staticmethod
        def pack(username: str, password: str) -> bytes:
            username_bytes = WireProtocol.pack_string(username)
            password_hash = hashlib.sha256(password.encode()).digest()
            return struct.pack(
                f'>HbH{len(username_bytes)}s32s',
                3 + len(username_bytes) + 32,  # length
                0x03,                          # request type
                len(username_bytes),           # username length
                username_bytes,                # username
                password_hash                  # hashed password
            )

    @dataclass
    class Login:
        @staticmethod
        def pack(username: str, password: str) -> bytes:
            username_bytes = WireProtocol.pack_string(username)
            password_hash = hashlib.sha256(password.encode()).digest()
            return struct.pack(
                f'>HbH{len(username_bytes)}s32s',
                3 + len(username_bytes) + 32,  # length
                0x05,                          # request type
                len(username_bytes),           # username length
                username_bytes,                # username
                password_hash                  # hashed password
            )
        
        @staticmethod
        def unpack_response(data: bytes) -> tuple[bool, bytes, int]:
            length, type_code, status = struct.unpack('>HbbB', data[:4])
            session_token = data[4:20]
            unread_count = struct.unpack('>I', data[20:24])[0]
            return (status == 0x00, session_token, unread_count)

    @dataclass
    class SendMessage:
        @staticmethod
        def pack(user_id: int, recipient_id: int, session_token: bytes, message: str) -> bytes:
            message_bytes = WireProtocol.pack_string(message)
            return struct.pack(
                f'>HbHH16sI{len(message_bytes)}s',
                7 + 16 + len(message_bytes),  # length
                0x13,                         # request type
                user_id,                      # user ID
                recipient_id,                 # recipient ID
                session_token,                # session token
                len(message_bytes),           # message length
                message_bytes                 # message content
            )

# Example usage:
def example():
    # Check username
    check_username_request = WireProtocol.CheckUsername.pack("testuser")
    
    # Create account
    create_account_request = WireProtocol.CreateAccount.pack("testuser", "password123")
    
    # Login
    login_request = WireProtocol.Login.pack("testuser", "password123")
    
    # Send message
    session_token = b'0' * 16  # Example session token
    message_request = WireProtocol.SendMessage.pack(1, 2, session_token, "Hello, world!")
    
    return check_username_request, create_account_request, login_request, message_request
