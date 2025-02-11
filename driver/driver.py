import hashlib
import time
import tkinter as tk
from tkinter import ttk
from typing import Tuple, Optional

from .core_structures import (
    GlobalUserBase,
    GlobalUserTrie,
    GlobalSessionTokens,
    GlobalMessageBase,
    GlobalConversations
)
from .core_entities import User, Message
pass
user_base = GlobalUserBase()
user_trie = GlobalUserTrie()
session_tokens = GlobalSessionTokens()
message_base = GlobalMessageBase()
conversations = GlobalConversations()

# BACKEND-BASED FUNCTIONS START
# FUNCTIONS 1 + 2
def create_account(username: str, hashed_password: str) -> str:
    # Create account from given username and password
    existing_user = user_trie.trie.get(username)
    if existing_user:
        raise AssertionError("Username already exists")

    if user_base._deleted_user_ids:
        user_id = user_base._deleted_user_ids.pop()
    else:
        user_id = user_base._next_user_id
        user_base._next_user_id += 1

    print(f"Creating new user with ID {user_id} and username {username}")
    # Create user
    new_user = User(user_id, username, hashed_password)
    # Add to user base
    user_base.users[user_id] = new_user
    # Add to trie
    user_trie.trie.add(username, new_user)
    
    print(f"User created successfully. Generating session token...")
    token = generate_session_token(user_id)
    return token

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token(user_id: int) -> str:
    # TODO: add time-based expiration
    token = hashlib.sha256(f"{user_id}_{hash(time.time())}".encode()).hexdigest()
    session_tokens.tokens[user_id] = token
    return token

def check_password(username: str, hashed_password: str) -> str:
    print(f"Checking password for user: {username}")
    checked_user = user_trie.trie.get(username)
    if not checked_user:
        print(f"User {username} not found")
        raise AssertionError("User not found")
    print(f"Found user, comparing passwords")
    if checked_user.passwordHash != hashed_password:
        raise AssertionError("Invalid password")
    return generate_session_token(checked_user.userID)

# FUNCTION 3
def list_accounts(wildcard_username: str) -> list[str]:
    # Return list of usernames matching wildcard pattern within trie
    matching_usernames = user_trie.trie.regex_search(wildcard_username, return_values=False) or []
    return sorted(matching_usernames)

# FUNCTION 4
def send_message(sender_id: int, recipient_id: int, message_content: str) -> bool:
    """
    Send a message from one user to another, handling message storage and notification.
    
    Args:
        sender_id (int): User ID of the message sender
        recipient_id (int): User ID of the message recipient
        message_content (str): Content of the message to be sent

    Returns:
        bool: True if message was sent successfully, False otherwise
    """
    # Validate users exist
    if sender_id not in user_base.users or recipient_id not in user_base.users:
        return False

    # Get message ID
    if message_base._deleted_message_ids:
        message_id = message_base._deleted_message_ids.pop()
    else:
        message_id = message_base._next_message_id
        message_base._next_message_id += 1

    # Check if recipient is online
    is_recipient_online = recipient_id in session_tokens.tokens

    # Create message
    new_message = Message(
        uid=message_id,
        contents=message_content,
        sender_id=sender_id,
        receiver_id=recipient_id,
        has_been_read=False  # Start as unread for recipient
    )

    print(f"Creating message with ID {message_id} from {sender_id} to {recipient_id}")

    # Store message
    message_base.messages[message_id] = new_message
    print(f"Stored message in message_base")
    
    # Add to conversation history
    conversation_key = tuple(sorted([sender_id, recipient_id]))
    if conversation_key not in conversations.conversations:
        conversations.conversations[conversation_key] = []
    conversations.conversations[conversation_key].append(new_message)
    print(f"Added message to conversation history between {sender_id} and {recipient_id}")
    
    # Update recent conversations
    user_base.users[sender_id].update_recent_conversant(recipient_id)
    user_base.users[recipient_id].update_recent_conversant(sender_id)
    
    # Add to recipient's unread messages
    user_base.users[recipient_id].unreadMessages.append(message_id)
    print(f"Added message {message_id} to {recipient_id}'s unread messages")
    
    # Create a copy of the message that's marked as read for the sender
    sender_message = Message(
        uid=message_id,
        contents=message_content,
        sender_id=sender_id,
        receiver_id=recipient_id,
        has_been_read=True  # Always read for sender
    )
    message_base.messages[message_id] = sender_message
    
    return True

# FUNCTION 5
def read_messages(user_id: int, message_quantity: int) -> list:
    """
    Process unread messages for a user, marking them as read and removing from unread queue.
    
    Args:
        user_id (int): ID of user whose messages to process
        message_quantity (int): Maximum number of messages to process
        
    Returns:
        list: List of messages that were read
    """
    assert(user_id in user_base.users)

    user = user_base.users[user_id]
    read_messages = []
    
    # Process all unread messages
    while user.unreadMessages and len(read_messages) < message_quantity:
        message_id = user.unreadMessages.popleft()
        message = message_base.messages.get(message_id)
        if not message:
            continue
            
        # Mark message as read in message_base
        message.has_been_read = True
        
        # Mark message as read in conversations
        conversation_key = tuple(sorted([message.sender_id, message.receiver_id]))
        if conversation_key in conversations.conversations:
            for msg in conversations.conversations[conversation_key]:
                if msg.uid == message_id:
                    msg.has_been_read = True
                    break
            
        message.has_been_read = True
        read_messages.append(message)
    
    return read_messages
    
# FUNCTION 6
def delete_message(message_uid: int):
    """
    Delete a message from the system, cleaning up all related references.
    
    This function performs a complete cleanup of a message across all system components:
    - Removes the message from the global message base
    - Removes it from the receiver's unread messages queue if present
    - Removes it from the conversation history
    - Recycles the message ID for future use
    
    Args:
        message_uid (int): The unique identifier of the message to delete
        
    Returns:
        bool: True if message was successfully deleted, False if message wasn't found
    """
    message = message_base.messages.get(message_uid)
    if not message:
        return False

    sender_id = message.sender_id
    sender = user_base.users.get(sender_id)
    receiver_id = message.receiver_id
    receiver = user_base.users.get(receiver_id)

    if not message.has_been_read and receiver:
            receiver.unread_messages.remove(message_uid)
            
    del message_base.messages[message_uid]
    message_base._deleted_message_ids.add(message_uid)

    conversation_key = tuple(sorted([sender_id, receiver_id]))
    if conversation_key in conversations.conversations:
        conversation = conversations.conversations[conversation_key]
        conversations.conversations[conversation_key] = [
            msg for msg in conversation if msg.uid != message_uid
        ]

        if not receiver or not conversations.conversations[conversation_key]:
            sender.recent_conversants.remove(receiver_id)
            if receiver:
                receiver.recent_conversants.remove(sender_id)

    return True

# (TODO: support deleting whole conversation? for later)

# FUNCTION 7
def delete_account(user_id: int) -> bool:
    """
    Delete a user account and handle cleanup of related data.
    
    Args:
        user_id (int): ID of the user account to delete
        
    Returns:
        bool: True if account was successfully deleted
    """
    try:
        # Remove from session tokens if logged in
        if user_id in session_tokens.tokens:
            del session_tokens.tokens[user_id]
        
        # Get user
        user = user_base.users[user_id]
        
        # Delete unread messages
        for unread_message_uid in user.unreadMessages:
            delete_message(unread_message_uid)
        
        # Delete all conversations involving user
        for conv_key in list(conversations.conversations.keys()):
            if user_id in conv_key:
                for msg in conversations.conversations[conv_key]:
                    delete_message(msg.uid)
                del conversations.conversations[conv_key]
        
        # Remove from trie
        user_trie.trie.delete(user.username)
        
        # Remove from user base
        del user_base.users[user_id]
        
        # Add user ID back to pool
        user_base._deleted_user_ids.add(user_id)
        
        return True
    except Exception as e:
        print(f"Error deleting account: {e}")
        return False
    user_trie.trie.remove(user.username)

    if user_id in session_tokens.tokens:
        del session_tokens.tokens[user_id]

    return True
    
    
# GUI FUNCTIONS START
def create_window() -> Tuple[bool, str, Optional[str]]:
    root = tk.Tk()
    root.title("Login System")
    root.geometry("400x500")  # Made taller to accommodate conversation list

    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Previous variables remain the same
    username_entry = None
    password_entry = None
    error_label = None
    current_username = None
    current_user = None  # Added to store the User object
    
    def show_logged_in_screen():
        nonlocal current_username, current_user
        for widget in main_frame.winfo_children():
            widget.destroy()

        # Welcome message at the top
        ttk.Label(main_frame, text=f"Welcome, {current_username}!").grid(row=0, pady=10)
        
        # Create a frame for recent conversations
        conversations_frame = ttk.Frame(main_frame)
        conversations_frame.grid(row=1, pady=10, sticky="nsew")
        
        # Add header for recent conversations
        ttk.Label(conversations_frame, text="Recent Conversations:", 
                 font=('Helvetica', 10, 'bold')).grid(row=0, pady=(0, 10))
        
        # For each recent conversant, create a styled frame
        for idx, user_id in enumerate(current_user.recent_conversants):
            # Get the username for this user_id
            contact_user = user_base.users.get(user_id)
            if contact_user:
                # Create a frame for this conversation with a border
                conv_frame = ttk.Frame(conversations_frame, relief="solid", borderwidth=1)
                conv_frame.grid(row=idx+1, pady=5, sticky="ew", padx=5)
                
                # Add the username to the frame
                ttk.Label(conv_frame, text=contact_user.username, 
                         padding=10).grid(row=0, column=0)

        # Logout button at the bottom
        ttk.Button(main_frame, text="Logout", 
                  command=lambda: show_username_screen()).grid(row=2, pady=20)

    def handle_password_submit():
        # Modified to store the user object
        nonlocal password_entry, error_label, current_username, current_user
        password = hash_password(password_entry.get())
        user = user_trie.trie.get(current_username)
        
        success = False
        if user:  # Login flow
            if check_password(current_username, password):
                token = generate_session_token(user.userID)
                current_user = user
                success = True
        else:  # Account creation flow
            token = create_account(current_username, password)
            current_user = user_trie.trie.get(current_username)
            success = True
            
        if success:
            show_logged_in_screen()
            return
            
        error_label.config(text="Invalid password")


    def show_password_screen():
        # This function shows the password entry screen, customized based on whether
        # we're creating a new account or logging into an existing one
        nonlocal password_entry, error_label, current_username
        
        for widget in main_frame.winfo_children():
            widget.destroy()
            
        user_exists = user_trie.trie.get(current_username) is not None
        
        # Show appropriate header based on whether user exists
        header_text = f"Log into {current_username}" if user_exists else f"Create account for {current_username}"
        ttk.Label(main_frame, text=header_text).grid(row=0, pady=10)
        
        # Password entry section
        pass_frame = ttk.Frame(main_frame)
        pass_frame.grid(row=1, pady=10)
        ttk.Label(pass_frame, text="Password: ").pack(side=tk.LEFT, padx=5)
        password_entry = ttk.Entry(pass_frame, show="*", width=30)
        password_entry.pack(side=tk.LEFT)
        
        # Submit button and error label
        ttk.Button(main_frame, text="Submit", 
                  command=handle_password_submit).grid(row=2, pady=10)
        error_label = ttk.Label(main_frame, text="", foreground="red")
        error_label.grid(row=3, pady=5)
        
        # Back button to return to username screen
        ttk.Button(main_frame, text="Back", 
                  command=show_username_screen).grid(row=4, pady=10)
        
        password_entry.focus()

    def handle_username_submit():
        # This function validates the username and transitions to the password screen
        nonlocal username_entry, error_label, current_username
        username = username_entry.get()
        
        if username:  # If username is not empty
            current_username = username
            show_password_screen()
        else:
            error_label.config(text="Please enter a username")

    def show_username_screen():
        # This function shows the initial username entry screen
        nonlocal username_entry, error_label
        
        for widget in main_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(main_frame, text="Enter Username").grid(row=0, pady=10)
        
        # Username entry section
        user_frame = ttk.Frame(main_frame)
        user_frame.grid(row=1, pady=10)
        ttk.Label(user_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        username_entry = ttk.Entry(user_frame, width=30)
        username_entry.pack(side=tk.LEFT)
        
        # Submit button and error label
        ttk.Button(main_frame, text="Next", 
                  command=handle_username_submit).grid(row=2, pady=10)
        error_label = ttk.Label(main_frame, text="", foreground="red")
        error_label.grid(row=3, pady=5)
        
        username_entry.focus()
    
    # Start with the username screen
    show_username_screen()
    root.mainloop()
    return False, "Closed", None


def populate_test_data():
    """Creates some test users and establishes conversation history between them."""
    # Create some test users
    usernames = ["alice", "bob", "charlie", "david", "eve"]
    test_password = hash_password("test123")
    
    # Create all users first
    for username in usernames:
        if not user_trie.trie.get(username):
            create_account(username, test_password)
    
    # Get the User objects
    users = {username: user_trie.trie.get(username) for username in usernames}
    
    # Set up some recent conversations for Alice
    alice = users["alice"]
    # Add bob, charlie, and eve as recent conversants
    alice.recent_conversants = [
        users["bob"].userID,
        users["charlie"].userID,
        users["eve"].userID
    ]
    
    # Set up some conversations for Bob
    bob = users["bob"]
    bob.recent_conversants = [
        users["alice"].userID,
        users["david"].userID
    ]
    users["eve"].recent_conversants = [users["alice"].userID]

    acts = list_accounts("*")
    print(acts)

if __name__ == "__main__":
    # Populate test data before starting the application
    populate_test_data()
    
    # Print out the test accounts for easy reference
    print("Test accounts created:")
    print("Username: alice, Password: test123")
    print("Username: bob, Password: test123")
    print("Username: charlie, Password: test123")
    print("Username: david, Password: test123")
    print("Username: eve, Password: test123")
    
    create_window()


    pass

    
