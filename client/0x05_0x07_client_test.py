import socket
from typing import Optional
import time
from socket_handler import Client

def test_login_logout_flow():
    client = Client(host = "127.0.0.1", port = 65432, use_json = False)
    client.connect()
    
    try:
        # Step 1: Create test account
        test_username = "alice"
        test_password = "password123"
        
        # First check if username is available
        username_available = client.search_username(test_username)
        if username_available:
            print(f"Test 1 - Username '{test_username}' is available, creating account...")
            session_token = client.create_account(test_username, test_password)
            print(f"Account created with session token: {session_token}")
        else:
            print(f"Test 1 - Username '{test_username}' already exists, proceeding with login tests...")
        
        # Step 2: Test login
        success, token, unread_count = client.log_into_account(test_username, test_password)
        print(f"\nTest 2 - Login attempt:")
        print(f"Success: {success}")
        print(f"Token: {token}")
        print(f"Unread messages: {unread_count}")
        
        if not success:
            raise Exception("Login failed")
            
        # Step 3: Test logout
        # Note: In a real implementation, you'd get the user_id from somewhere
        # For testing, we can use a dummy value like 1
        user_id = 1
        client.log_out_of_account(user_id, token)
        print(f"\nTest 3 - Logout successful")
        
        client.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        client.disconnect()
        return False

if __name__ == "__main__":
    test_result = test_login_logout_flow()
    print(f"\nAll tests {'passed' if test_result else 'failed'}")
