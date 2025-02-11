import socket
from typing import Optional
import time
from socket_handler import Client

def test_create_account():
    client = Client()
    client.connect()
    
    try:
        # Test creating account for 'alice'
        session_token = client.create_account("alice", "password123")
        print(f"Test 1 - Account created for 'alice'. Session token: {session_token}")
        
        # Verify token is the correct length (64 characters as hex string)
        if len(session_token) != 64:
            raise Exception(f"Invalid token length: {len(session_token)}")
            
        client.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        client.disconnect()
        return False

if __name__ == "__main__":
    test_result = test_create_account()
    print(f"\nAll tests {'passed' if test_result else 'failed'}")
