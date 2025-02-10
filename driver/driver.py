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


if __name__ == "__main__":
    handle_account_creation()
