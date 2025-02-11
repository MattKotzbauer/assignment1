import socket
from typing import Optional
import time
from socket_handler import Client

def test_messaging_operations():
    client1 = Client()
    client2 = Client()
    client1.connect()
    client2.connect()
    
    try:
        # Step 1: Create test accounts and login
        test_user1 = "testuser1"
        test_user2 = "testuser2"
        test_password = "testpass123"
        
        # Create/login first user
        username1_available = client1.search_username(test_user1)
        if username1_available:
            session_token1 = client1.create_account(test_user1, test_password)
            print(f"Created first test account")
        else:
            success, session_token1, _ = client1.log_into_account(test_user1, test_password)
            if not success:
                raise Exception("Login failed for first test user")
            print(f"Logged in with first test account")
            
        # Create/login second user
        username2_available = client2.search_username(test_user2)
        if username2_available:
            session_token2 = client2.create_account(test_user2, test_password)
            print(f"Created second test account")
        else:
            success, session_token2, _ = client2.log_into_account(test_user2, test_password)
            if not success:
                raise Exception("Login failed for second test user")
            print(f"Logged in with second test account")

        # Step 2: Send messages between users
        user1_id = 1  # We know these IDs because they're the first two accounts
        user2_id = 2
        session_token1_bytes = bytes.fromhex(session_token1)
        session_token2_bytes = bytes.fromhex(session_token2)
        
        print("\nTest 1 - Sending messages:")
        test_message1 = "Hello from user1!"
        test_message2 = "Hello back from user2!"
        
        client1.send_message(user1_id, session_token1_bytes, user2_id, test_message1)
        client2.send_message(user2_id, session_token2_bytes, user1_id, test_message2)
        print("Messages sent successfully")
        
        # Step 3: Display conversation
        print("\nTest 2 - Displaying conversation:")
        conversation = client1.display_conversation(user1_id, session_token1_bytes, user2_id)
        print(f"Conversation retrieved: {conversation}")
        
        # Step 4: Read messages
        print("\nTest 3 - Reading messages:")
        client1.read_messages(user1_id, session_token1_bytes, 5)  # Read up to 5 messages
        client2.read_messages(user2_id, session_token2_bytes, 5)
        print("Messages marked as read")
        
        # Step 5: Delete a message
        print("\nTest 4 - Deleting message:")
        if conversation:
            first_message_id = conversation[0][0]  # Get ID of first message
            client1.delete_message(user1_id, first_message_id, session_token1_bytes)
            print(f"Deleted message with ID: {first_message_id}")
        
        # Step 6: Delete accounts
        print("\nTest 5 - Deleting accounts:")
        client1.delete_account(user1_id, session_token1_bytes)
        client2.delete_account(user2_id, session_token2_bytes)
        print("Accounts deleted successfully")
        
        client1.disconnect()
        client2.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        client1.disconnect()
        client2.disconnect()
        return False

if __name__ == "__main__":
    test_result = test_messaging_operations()
    print(f"\nAll tests {'passed' if test_result else 'failed'}")
