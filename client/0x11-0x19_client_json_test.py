# Termination test for primary account-based backend driver functions

import socket
import time
from socket_handler import Client

def test_messaging_operations():

    client1 = Client(host="127.0.0.1", port=65432, use_json = True)
    client2 = Client(host="127.0.0.1", port=65432, use_json = True)
    client1.connect()
    client2.connect()
    
    try:
        # Create/login test accounts
        test_user1, test_user2 = "testuser1", "testuser2"
        test_password = "testpass123"
        
        # First user setup
        if client1.search_username(test_user1):
            session_token1 = client1.create_account(test_user1, test_password)
            print("Test 1a: Created first account")
        else:
            success, session_token1, _ = client1.log_into_account(test_user1, test_password)
            if not success:
                raise Exception("Login failed for first user")
            print("Test 1a: Logged into first account")
            
        # Second user setup
        if client2.search_username(test_user2):
            session_token2 = client2.create_account(test_user2, test_password)
            print("Test 1b: Created second account")
        else:
            success, session_token2, _ = client2.log_into_account(test_user2, test_password)
            if not success:
                raise Exception("Login failed for second user")
            print("Test 1b: Logged into second account")

        # Test message operations
        user1_id, user2_id = 1, 2
        
        # Send messages
        print("\nTest 2: Message Sending")
        client1.send_message(user1_id, session_token1, user2_id, "Hello from user1!")
        client2.send_message(user2_id, session_token2, user1_id, "Hello back from user2!")
        print("Messages sent successfully")
        
        # Display conversation
        print("\nTest 3: Conversation Display")
        conversation = client1.display_conversation(user1_id, session_token1, user2_id)
        if not conversation:
            raise Exception("No conversation retrieved")
        print(f"Retrieved {len(conversation)} messages")
        
        # Read messages
        print("\nTest 4: Message Reading")
        client1.read_messages(user1_id, session_token1, 5)
        client2.read_messages(user2_id, session_token2, 5)
        print("Messages marked as read")
        
        # Delete message
        print("\nTest 5: Message Deletion")
        if conversation:
            msg_id = conversation[0][0]
            client1.delete_message(user1_id, msg_id, session_token1)
            print(f"Deleted message {msg_id}")
        
        # Delete accounts
        print("\nTest 6: Account Deletion")
        client1.delete_account(user1_id, session_token1)
        client2.delete_account(user2_id, session_token2)
        print("Accounts deleted")
        
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
