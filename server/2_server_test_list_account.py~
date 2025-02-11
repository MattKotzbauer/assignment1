import driver
from core_entities import User

def create_list_accounts_packet(user_id: int, session_token: str, wildcard: str) -> bytes:
    wildcard_bytes = wildcard.encode('utf-8')
    wildcard_length = len(wildcard_bytes)
    
    # Calculate remaining length (1 byte opcode + 2 bytes user_id + 32 bytes token + 2 bytes wildcard length + wildcard)
    remaining_length = 1 + 2 + 32 + 2 + wildcard_length
    
    packet = (
        remaining_length.to_bytes(4, byteorder='big') +  # Length of remaining data
        bytes([0x09]) +                                  # Opcode 0x09
        user_id.to_bytes(2, byteorder='big') +          # User ID
        bytes.fromhex(session_token) +                  # Session token
        wildcard_length.to_bytes(2, byteorder='big') +  # Wildcard length
        wildcard_bytes                                  # Wildcard string
    )
    return packet

if __name__ == "__main__":
    # Set up test users and tokens
    test_users = [
        ("john", "foo", 1),
        ("jane", "bar", 2),
        ("james", "baz", 3)
    ]
    
    for username, password, user_id in test_users:
        user = User(user_id, username, password)
        driver.user_trie.trie.add(username, user)
        driver.session_tokens.tokens[user_id] = "a" * 64  # Mock token
    
    # Test Case 1: Exact match with valid token
    test_packet1 = create_list_accounts_packet(1, "a" * 64, "john")
    print("\nTest Case 1 - Search for 'john' with valid token:")
    print(f"Packet hex: {test_packet1.hex()}")
    
    # Test Case 2: Wildcard search with valid token
    test_packet2 = create_list_accounts_packet(1, "a" * 64, "j*")
    print("\nTest Case 2 - Search for 'j*' with valid token:")
    print(f"Packet hex: {test_packet2.hex()}")
    
    # Test Case 3: Search with invalid token
    test_packet3 = create_list_accounts_packet(1, "b" * 64, "john")
    print("\nTest Case 3 - Search with invalid token:")
    print(f"Packet hex: {test_packet3.hex()}")
    
    # Simulate processing these packets
    def simulate_packet_processing(packet: bytes):
        if len(packet) < 7:
            print("Packet too short")
            return
            
        packet_length = int.from_bytes(packet[0:4], byteorder='big')
        opcode = packet[4]
        user_id = int.from_bytes(packet[5:7], byteorder='big')
        provided_token = packet[7:7+32]
        wildcard_length = int.from_bytes(packet[7+32:7+32+2], byteorder='big')
        wildcard = packet[7+32+2:7+32+2+wildcard_length].decode('utf-8')
        
        stored_token = driver.session_tokens.tokens.get(user_id)
        authenticated = stored_token and bytes.fromhex(stored_token) == provided_token
        matching_accounts = driver.list_accounts(wildcard) if authenticated else []
        
        print(f"Received packet for wildcard '{wildcard}':")
        print(f"- Packet length: {packet_length}")
        print(f"- User authenticated: {authenticated}")
        print(f"- Matching accounts: {matching_accounts}")
        
        count = len(matching_accounts)
        response_body = bytes([0x10]) + count.to_bytes(2, byteorder='big')
        for username in matching_accounts:
            username_bytes = username.encode('utf-8')
            uname_length = len(username_bytes)
            response_body += uname_length.to_bytes(2, byteorder='big') + username_bytes
            
        response_length = len(response_body).to_bytes(4, byteorder='big')
        full_response = response_length + response_body
        print(f"Response packet hex: {full_response.hex()}")
    
    print("\nProcessing Test Case 1:")
    simulate_packet_processing(test_packet1)
    
    print("\nProcessing Test Case 2:")
    simulate_packet_processing(test_packet2)
    
    print("\nProcessing Test Case 3:")
    simulate_packet_processing(test_packet3)
