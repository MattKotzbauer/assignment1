import socket
from typing import Optional
import time
from socket_handler import Client

def test_list_accounts():
    client = Client()
    client.connect()
    
    try:
        # Step 1: Create test account and login
        test_username = "alice"
        test_password = "password123"
        
        # First check if username is available
        username_available = client.search_username(test_username)
        if username_available:
            session_token = client.create_account(test_username, test_password)
            print(f"Test 1 - Account created with session token: {session_token}")
        else:
            success, session_token, _ = client.log_into_account(test_username, test_password)
            if not success:
                raise Exception("Login failed")
            print(f"Test 1 - Logged in with existing account")
        
        # Step 2: Test listing accounts with different wildcards
        user_id = 1  # Using same dummy value as logout test
        
        # Test exact match
        matching_accounts = client.list_accounts(user_id, session_token, "alice")
        print(f"\nTest 2a - Exact match search:")
        print(f"Found accounts: {matching_accounts}")
        
        # Test wildcard search
        matching_accounts = client.list_accounts(user_id, session_token, "a*")
        print(f"\nTest 2b - Wildcard search:")
        print(f"Found accounts: {matching_accounts}")
        
        client.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        client.disconnect()
        return False

if __name__ == "__main__":
    test_result = test_list_accounts()
    print(f"\nAll tests {'passed' if test_result else 'failed'}")
