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

"""
def prompt_text(prompt: str)-> str:

    result = None
    def on_submit():
        nonlocal result
        result = entry.get()
        root.quit()

    root=tk.Tk()
    root.title("Input Required")
    
    frame = ttk.Frame(root, padding="10")
    frame.grid()

    ttk.Label(frame, text=prompt).grid(row=0)
    entry = ttk.Entry(frame, width = 30)
    entry.grid(row = 1, pady = 5)
    entry.focus()

    ttk.Button(frame, text = "Submit", command = on_submit).grid(row = 2)

    root.bind('<Return>', lambda e: on_submit())
    root.mainloop()
    root.destroy()
    return result

# (Output: success, message, session token)
def handle_account_creation() -> Tuple[bool, str, Optional[str]]:
    # (account creation entry point)
    # 1: prompt for username
    username = prompt_text("Enter desired username")
    # 2: check username against existing users
    user = user_trie.trie.get(username)
    if user:
        # 2a: if found, prompt for login
        hashed_password = prompt_text("User is already registered. Please enter password")
        # (check password against existing entry)
        if check_password(username, hashed_password):
            token = generate_session_token(user.userID)
            return (True, "Login successful.", token)
        return (False, "Incorrect password.", None)
    else: 
        # 2b: if unfound, prompt for new password
        hashed_password = prompt_text("Username is available. Please enter password")
        token = create_account(username, hashed_password)
        return (True, "Created account.", token)
        # Create account with username and hash of desired password

"""

"""
def create_window() -> Tuple[bool, str, Optional[str]]:
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x300")  # Set window size
    
    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    
    def submit():
        username = user_entry.get()
        password = hash_password(pass_entry.get())
        user = user_trie.trie.get(username)
        
        if username and password:
            success = False
            if not user:
                token = create_account(username, password)
                success = True
            elif check_password(username, password):
                token = generate_session_token(user.userID)
                success = True
                
            if success:
                # Clear frame and show logged in view
                for widget in main_frame.winfo_children():
                    widget.destroy()
                ttk.Label(main_frame, text=f"Welcome, {username}!").grid(pady=10)
                ttk.Button(main_frame, text="Logout", command=lambda: show_login()).grid(pady=10)
                return
                
        # Show error if login failed
        error_label.config(text="Invalid credentials")
    
    def show_login():
        # Clear frame and show login view
        for widget in main_frame.winfo_children():
            widget.destroy()
            
        # Username row
        user_frame = ttk.Frame(main_frame)
        user_frame.grid(row=0, pady=10)
        ttk.Label(user_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        user_entry = ttk.Entry(user_frame, width=30)
        user_entry.pack(side=tk.LEFT)
        
        # Password row
        pass_frame = ttk.Frame(main_frame)
        pass_frame.grid(row=1, pady=10)
        ttk.Label(pass_frame, text="Password: ").pack(side=tk.LEFT, padx=5)
        pass_entry = ttk.Entry(pass_frame, show="*", width=30)
        pass_entry.pack(side=tk.LEFT)
        
        # Submit button and error label
        ttk.Button(main_frame, text="Submit", command=submit).grid(row=2, pady=10)
        error_label = ttk.Label(main_frame, text="", foreground="red")
        error_label.grid(row=3, pady=5)
        
        user_entry.focus()
    
    show_login()
    root.mainloop()
    return False, "Closed", None

if __name__ == "__main__":
    create_window()
"""

def create_window() -> Tuple[bool, str, Optional[str]]:
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x300")

    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Make these nonlocal so submit() can access them
    user_entry = None
    pass_entry = None
    error_label = None
    
    def submit():
        nonlocal user_entry, pass_entry, error_label
        username = user_entry.get()
        password = hash_password(pass_entry.get())
        user = user_trie.trie.get(username)
        
        if username and password:
            success = False
            if not user:
                token = create_account(username, password)
                success = True
            elif check_password(username, password):
                token = generate_session_token(user.userID)
                success = True
                
            if success:
                for widget in main_frame.winfo_children():
                    widget.destroy()
                ttk.Label(main_frame, text=f"Welcome, {username}!").grid(pady=10)
                ttk.Button(main_frame, text="Logout", command=lambda: show_login()).grid(pady=10)
                return
                
        error_label.config(text="Invalid credentials")
    
    def show_login():
        nonlocal user_entry, pass_entry, error_label
        for widget in main_frame.winfo_children():
            widget.destroy()
            
        user_frame = ttk.Frame(main_frame)
        user_frame.grid(row=0, pady=10)
        ttk.Label(user_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        user_entry = ttk.Entry(user_frame, width=30)
        user_entry.pack(side=tk.LEFT)
        
        pass_frame = ttk.Frame(main_frame)
        pass_frame.grid(row=1, pady=10)
        ttk.Label(pass_frame, text="Password: ").pack(side=tk.LEFT, padx=5)
        pass_entry = ttk.Entry(pass_frame, show="*", width=30)
        pass_entry.pack(side=tk.LEFT)
        
        ttk.Button(main_frame, text="Submit", command=submit).grid(row=2, pady=10)
        error_label = ttk.Label(main_frame, text="", foreground="red")
        error_label.grid(row=3, pady=5)
        
        user_entry.focus()
    
    show_login()
    root.mainloop()
    return False, "Closed", None

if __name__ == "__main__":
    create_window()

    
