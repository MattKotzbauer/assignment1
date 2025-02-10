import hashlib
import time
import tkinter as tk
from tkinter import ttk
from typing import Tuple, Optional
from core_structures import (
    GlobalUserBase,
    GlobalUserTrie,
    GlobalSessionTokens,
    GlobalMessageBase,
    GlobalConversations
)
from core_entities import User

user_base = GlobalUserBase()
user_trie = GlobalUserTrie()
session_tokens = GlobalSessionTokens()
message_base = GlobalMessageBase()
conversations = GlobalConversations()

# BACKEND-BASED FUNCTIONS START
def create_account(username: str, hashed_password: str) -> str:
    # Create account from given username and password
    assert not user_trie.trie.get(username)

    if user_base._deleted_user_ids:
        # (ok this just means we have to be very careful about deletions)
        user_id = user_base._deleted_user_ids.pop()
    else:
        user_id = user_base._next_user_id
        user_base._next_user_id += 1

    # Create user
    new_user = User(user_id, username, hashed_password)
    # (add to message base)
    user_base.users[user_id] = new_user
    # (add to trie)
    user_trie.trie.add(username, new_user)
    token = generate_session_token(user_id)
    return(token)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token(user_id: int) -> str:
    # TODO: add time-based expiration
    token = hashlib.sha256(f"{user_id}_{hash(time.time())}".encode()).hexdigest()
    session_tokens.tokens[user_id] = token
    return token

def check_password(username: str, hashed_password: str) -> bool:
    checked_user = user_trie.trie.get(username)
    assert(checked_user)
    return checked_user.passwordHash == hashed_password

# GUI FUNCTIONS START
def create_window() -> Tuple[bool, str, Optional[str]]:
    root = tk.Tk()
    root.title("Messenger")
    root.geometry("400x300")

    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Variables we need to access across different states of our interface
    username_entry = None
    password_entry = None
    error_label = None
    current_username = None  # Store username between screens
    
    def handle_password_submit():
        # This function handles the password submission for both login and account creation
        nonlocal password_entry, error_label, current_username
        password = hash_password(password_entry.get())
        user = user_trie.trie.get(current_username)
        
        success = False
        if user:  # Login flow
            if check_password(current_username, password):
                token = generate_session_token(user.userID)
                success = True
        else:  # Account creation flow
            token = create_account(current_username, password)
            success = True
            
        if success:
            # Show logged in screen
            for widget in main_frame.winfo_children():
                widget.destroy()
            ttk.Label(main_frame, text=f"Welcome, {current_username}!").grid(pady=10)
            ttk.Button(main_frame, text="Logout", 
                      command=lambda: show_username_screen()).grid(pady=10)
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

if __name__ == "__main__":
    create_window()
    
