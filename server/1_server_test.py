
import socket
import selectors
import types
from typing import Dict, Optional
from core_entities import Message, User
from socket_handler import Server
import driver

def create_username_check_packet(username: str) -> bytes:
    username_bytes = username.encode('utf-8')
    username_length = len(username_bytes)
    
    # Calculate remaining length (1 byte opcode + 2 bytes username length + username bytes)
    remaining_length = 1 + 2 + username_length
    
    packet = (
        remaining_length.to_bytes(4, byteorder='big') +  # Length of remaining data
        bytes([0x01]) +                                  # Opcode 0x01
        username_length.to_bytes(2, byteorder='big') +   # Username length
        username_bytes                                   # Username
    )
    print("packet: ")
    print(packet)
    return packet

if __name__ == "__main__":
    # Set up test user
    user_john = User(1, "john", "foo")
    driver.user_trie.trie.add("john", user_john)
    
    # Test Case 1: Check existing username "john"
    test_packet1 = create_username_check_packet("john")
    print("\nTest Case 1 - Checking existing username 'john':")
    print(f"Packet hex: {test_packet1.hex()}")
    
    # Test Case 2: Check non-existent username "alice"
    test_packet2 = create_username_check_packet("alice")
    print("\nTest Case 2 - Checking non-existent username 'alice':")
    print(f"Packet hex: {test_packet2.hex()}")
    
    # Simulate processing these packets
    def simulate_packet_processing(packet: bytes):
        if len(packet) < 7:
            print("Packet too short")
            return
            
        packet_length = int.from_bytes(packet[0:4], byteorder='big')
        opcode = packet[4]
        username_length = int.from_bytes(packet[5:7], byteorder='big')
        username = packet[7:7+username_length].decode('utf-8')
        
        user_exists = driver.user_trie.trie.get(username) is not None
        status = 0x01 if user_exists else 0x00
        
        print(f"Received packet for username '{username}':")
        print(f"- Packet length: {packet_length}")
        print(f"- Username length: {username_length}")
        print(f"- User exists: {user_exists}")
        print(f"- Status code: {status:#04x}")
        
        response_body = bytes([0x02, status])
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        print(f"Response packet hex: {full_response.hex()}")
    
    print("\nProcessing Test Case 1:")
    simulate_packet_processing(test_packet1)
    
    print("\nProcessing Test Case 2:")
    simulate_packet_processing(test_packet2)

    

"""
import socket
import selectors
import types
from typing import Dict, Optional
import driver
from core_entities import Message, User
from socket_handler import Server

if __name__ == "__main__":
    username_length = int.from_bytes(packet_content[5:7], byteorder='big')
    username = packet_content[7:7+username_length].decode('utf-8')
    user_exists = driver.user_trie.trie.get(username) is not None
    status = 0x01 if user_exists else 0x00
    print(f"Username '{username}' exists: {user_exists}. Sending status code {status:#04x}.")
    # Response format:
    #   1. Length (4 bytes) of remaining packet body (here: opcode + status = 1 + 1 = 2 bytes)
    #   2. Opcode 0x02 (1 byte)
    #   3. Status code (1 byte)
    #      - 0x00: username is available (client should send 0x03 register request)
    #      - 0x01: username is taken (client should send 0x05 login request)
    response_body = bytes([0x02, status])
    response_length = len(response_body).to_bytes(4, byteorder='big')
    full_response = response_length + response_body
"""
