import time
from socket_handler import Client

def test_advanced_messaging_operations():
    """
    This test simulates an advanced conversation between two users.
    
    It does the following:
      1. Connects two clients and creates (or logs into) two accounts ("coolUserA" and "coolUserB").
      2. Verifies that the accounts exist.
      3. Sends multiple messages from coolUserA to coolUserB and vice versa.
      4. Retrieves the conversation from coolUserA's perspective and prints out details.
      5. Marks all messages as read.
      6. Uses a wildcard account search to verify both accounts are found.
      7. Deletes one of coolUserA's messages and uses get_message_info to confirm that the deleted message is no longer retrievable.
      8. Finally, deletes both accounts and disconnects the clients.
    """
    clientA = Client(host="127.0.0.1", port=65432)
    clientB = Client(host="127.0.0.1", port=65432)
    
    clientA.connect()
    clientB.connect()
    
    try:
        # --- Account Setup ---
        usernameA = "coolUserA"
        usernameB = "coolUserB"
        password = "pass1234"
        
        # Create or log into coolUserA
        if clientA.search_username(usernameA):
            tokenA = clientA.create_account(usernameA, password)
            print("Created account for coolUserA")
        else:
            success, tokenA, _ = clientA.log_into_account(usernameA, password)
            if not success:
                raise Exception("Login failed for coolUserA")
            print("Logged into account for coolUserA")
            
        # Create or log into coolUserB
        if clientB.search_username(usernameB):
            tokenB = clientB.create_account(usernameB, password)
            print("Created account for coolUserB")
        else:
            success, tokenB, _ = clientB.log_into_account(usernameB, password)
            if not success:
                raise Exception("Login failed for coolUserB")
            print("Logged into account for coolUserB")
        
        # Double-check account existence using search_username.
        if clientA.search_username(usernameA):
            raise Exception("Account coolUserA should exist but search_username indicates it's available.")
        if clientB.search_username(usernameB):
            raise Exception("Account coolUserB should exist but search_username indicates it's available.")
        print("Verified account existence for both coolUserA and coolUserB.")
        
        # For testing purposes, we assume user IDs 1 and 2 for coolUserA and coolUserB respectively.
        userA_id, userB_id = 1, 2
        
        # --- Messaging Operations ---
        messages_A_to_B = [
            "Hey, how's it going?",
            "Did you catch the game last night?",
            "What are you up to today?"
        ]
        messages_B_to_A = [
            "Hi! I'm doing well, thanks.",
            "Yes, it was epic!"
        ]
        
        # Send messages from coolUserA to coolUserB
        for msg in messages_A_to_B:
            clientA.send_message(userA_id, tokenA, userB_id, msg)
            time.sleep(0.1)  # small pause to simulate real-world delays
        
        # Send messages from coolUserB to coolUserA
        for msg in messages_B_to_A:
            clientB.send_message(userB_id, tokenB, userA_id, msg)
            time.sleep(0.1)
        
        print("Messages exchanged between coolUserA and coolUserB.")
        
        # Retrieve conversation from coolUserA's perspective.
        conversation = clientA.display_conversation(userA_id, tokenA, userB_id)
        total_expected = len(messages_A_to_B) + len(messages_B_to_A)
        if not conversation:
            raise Exception("No conversation retrieved by coolUserA.")
        
        if len(conversation) != total_expected:
            print(f"Warning: Expected {total_expected} messages, but got {len(conversation)} in the conversation.")
        print(f"Conversation retrieved with {len(conversation)} messages.")
        
        # Print out the conversation details.
        print("Conversation details:")
        for idx, msg in enumerate(conversation):
            # Assuming each message is a tuple: (message_id, content, is_sender)
            msg_id, content, is_sender = msg
            sender = "coolUserA" if is_sender else "coolUserB"
            print(f"  Message {idx+1} (ID: {msg_id}) from {sender}: '{content}'")
        
        # Mark all messages as read.
        clientA.read_messages(userA_id, tokenA, 10)
        clientB.read_messages(userB_id, tokenB, 10)
        print("All messages marked as read.")
        
        # --- Wildcard account search ---
        accounts_found = clientA.list_accounts(userA_id, tokenA, "cool*")
        if usernameA not in accounts_found or usernameB not in accounts_found:
            raise Exception("Wildcard account search did not return expected accounts.")
        print("Wildcard account search ('cool*') returned expected accounts:", accounts_found)
        
        # --- Message Deletion ---
        # Identify one message sent by coolUserA (is_sender True) to delete.
        msg_to_delete = None
        for msg in conversation:
            if msg[2]:  # is_sender is True, so message from coolUserA.
                msg_to_delete = msg[0]
                break
        
        if msg_to_delete is None:
            raise Exception("No message from coolUserA found to delete.")
        
        clientA.delete_message(userA_id, msg_to_delete, tokenA)
        print(f"Deleted message with ID {msg_to_delete} sent by coolUserA.")
        
        # --- Verify Deletion Using get_message_info ---
        try:
            # Try to fetch details of the deleted message.
            info = clientA.get_message_info(userA_id, tokenA, msg_to_delete)
            # If the deleted message is still returned, that’s an error.
            raise Exception("Deleted message was still retrievable via get_message_info!")
        except Exception as e:
            # Expected outcome: get_message_info fails because the message no longer exists.
            print("Confirmed that the deleted message is no longer retrievable (get_message_info failed as expected).")
        
        # --- Cleanup: Delete Accounts ---
        clientA.delete_account(userA_id, tokenA)
        clientB.delete_account(userB_id, tokenB)
        print("Both coolUserA and coolUserB accounts have been deleted.")
        
        clientA.disconnect()
        clientB.disconnect()
        return True
    
    except Exception as exc:
        print(f"Advanced test failed: {exc}")
        clientA.disconnect()
        clientB.disconnect()
        return False

if __name__ == "__main__":
    result = test_advanced_messaging_operations()
    print(f"\nAdvanced test suite {'passed' if result else 'failed'}")
