# Correctness test for primary account-based backend driver functions

import socket
import time
from socket_handler import Client

def test_messaging_operations():
    client1 = Client(host="127.0.0.1", port=65432)
    client2 = Client(host="127.0.0.1", port=65432)
    client1.connect()
    client2.connect()
    
    try:
        # Define test account credentials.
        test_user1, test_user2 = "testuser1", "testuser2"
        test_password = "testpass123"
        
        # ---------------------------
        # Account creation / login
        # ---------------------------
        # For the first account: if search_username returns True, then the username is available
        # (i.e. no account exists) so we create an account; otherwise, we log in.
        if client1.search_username(test_user1):
            session_token1 = client1.create_account(test_user1, test_password)
            print("Test 1a: Created first account")
        else:
            success, session_token1, _ = client1.log_into_account(test_user1, test_password)
            if not success:
                raise Exception("Login failed for first user")
            print("Test 1a: Logged into first account")
            
        if client2.search_username(test_user2):
            session_token2 = client2.create_account(test_user2, test_password)
            print("Test 1b: Created second account")
        else:
            success, session_token2, _ = client2.log_into_account(test_user2, test_password)
            if not success:
                raise Exception("Login failed for second user")
            print("Test 1b: Logged into second account")
        
        # -----------------------------------------------------------
        # Verify that the created accounts now exist (i.e. search returns False)
        # -----------------------------------------------------------
        if client1.search_username(test_user1):
            raise Exception("Verification failed: First account does not appear to exist after creation.")
        else:
            print("Test 1a-verify: First account exists (username not available)")
            
        if client2.search_username(test_user2):
            raise Exception("Verification failed: Second account does not appear to exist after creation.")
        else:
            print("Test 1b-verify: Second account exists (username not available)")
            
        # ----------------------------------
        # Test message operations between accounts
        # ----------------------------------
        user1_id, user2_id = 1, 2
        
        print("\nTest 2: Message Sending")
        client1.send_message(user1_id, session_token1, user2_id, "Hello from user1!")
        client2.send_message(user2_id, session_token2, user1_id, "Hello back from user2!")
        print("Messages sent successfully")
        
        print("\nTest 3: Conversation Display")
        conversation = client1.display_conversation(user1_id, session_token1, user2_id)
        if not conversation:
            raise Exception("No conversation retrieved")
        print(f"Retrieved {len(conversation)} messages")
        
        print("\nTest 4: Message Reading")
        client1.read_messages(user1_id, session_token1, 5)
        client2.read_messages(user2_id, session_token2, 5)
        print("Messages marked as read")
        
        print("\nTest 5: Message Deletion")
        if conversation:
            msg_id = conversation[0][0]
            client1.delete_message(user1_id, msg_id, session_token1)
            print(f"Deleted message {msg_id}")
        
        # ----------------------------------
        # Delete accounts
        # ----------------------------------
        print("\nTest 6: Account Deletion")
        client1.delete_account(user1_id, session_token1)
        client2.delete_account(user2_id, session_token2)
        print("Accounts deleted")
        
        # -----------------------------------------------------------
        # Verify that the accounts no longer exist (i.e. search returns True)
        # -----------------------------------------------------------
        print("\nTest 7: Verify Account Deletion")
        if not client1.search_username(test_user1):
            raise Exception("Verification failed: First account still exists after deletion.")
        else:
            print("Test 7a: First account deletion confirmed (username available)")
            
        if not client2.search_username(test_user2):
            raise Exception("Verification failed: Second account still exists after deletion.")
        else:
            print("Test 7b: Second account deletion confirmed (username available)")
        
        client1.disconnect()
        client2.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        client1.disconnect()
        client2.disconnect()
        return False

if __name__ == "__main__":
    result = test_messaging_operations()
    print(f"\nTest suite {'passed' if result else 'failed'}")

