import tkinter as tk
from tkinter import ttk, messagebox
import threading
from queue import Queue
import os
import sys
import hashlib

# Add the driver directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'driver'))

from driver.driver import (
    create_account, check_password, list_accounts,
    send_message, read_messages, delete_message, generate_session_token,
    hash_password, user_base, user_trie, conversations
)
from driver.core_entities import Message, User

def get_username_by_id(user_id: int) -> str:
    """Get username by user ID"""
    print(f"Looking up username for ID: {user_id}")
    user = user_base.users.get(user_id)
    if user:
        print(f"Found user: {user.username}")
        return user.username
    print(f"No user found for ID: {user_id}")
    return None

def get_user_by_username(username: str) -> User:
    """Get user object by username"""
    print(f"Looking up user object for username: {username}")
    user = user_trie.trie.get(username)
    if user:
        print(f"Found user object: ID={user.userID}")
    else:
        print(f"No user object found for username: {username}")
    return user

class ChatInterface:
    def __init__(self):
        print("Initializing ChatInterface...")
        # Initialize the main window
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("800x600")  # Set a reasonable default size
        
        # Message queue for thread-safe communication
        self.message_queue = Queue()
        
        # User session data
        self.current_user_id = None
        self.current_token = None
        self.message_ids = []
        
        # Configure grid weights for the root window
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        print("Showing login screen...")
        # Show login screen first
        self.show_login_screen()
    
    def show_login_screen(self):
        print("Setting up login screen...")
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create login frame
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.grid(row=0, column=0)
        
        # Configure grid weights for centering
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(login_frame, text="Chat Application", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Instructions
        instructions = ttk.Label(login_frame, 
                               text="Enter username and password\nNew users will be registered automatically",
                               justify=tk.CENTER)
        instructions.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        # Username field
        ttk.Label(login_frame, text="Username:").grid(row=2, column=0, pady=5, padx=5, sticky="e")
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.grid(row=2, column=1, pady=5, padx=5, sticky="ew")
        
        # Password field
        ttk.Label(login_frame, text="Password:").grid(row=3, column=0, pady=5, padx=5, sticky="e")
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.grid(row=3, column=1, pady=5, padx=5, sticky="ew")
        
        # Login button
        self.login_button = ttk.Button(login_frame, text="Login", command=self.handle_login)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Status label
        self.status_label = ttk.Label(login_frame, text="", foreground="black")
        self.status_label.grid(row=5, column=0, columnspan=2, pady=5)
        
        # Error label
        self.error_label = ttk.Label(login_frame, text="", foreground="red")
        self.error_label.grid(row=6, column=0, columnspan=2, pady=5)
        
        # Bind Enter key to login
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
        self.password_entry.bind('<Return>', lambda e: self.handle_login())
        
        # Set focus to username entry
        self.username_entry.focus()
        print("Login screen setup complete")
    
    def show_main_screen(self):
        print("\n=== Setting up main screen... ===\n")
        try:
            # Clear login screen
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Create the main container frame with padding
            self.main_frame = ttk.Frame(self.root, padding="5")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Configure grid weight for resizing
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            self.main_frame.columnconfigure(1, weight=1)  # Message area column
            self.main_frame.rowconfigure(0, weight=1)     # Message area row
            
            # Create the three main sections
            self.create_user_list()    # Left panel
            self.create_message_area() # Center panel
            self.create_input_area()   # Bottom panel
            
            # Add logout button
            ttk.Button(self.main_frame, text="Logout", command=self.handle_logout).grid(row=2, column=0, pady=5)
    
            # Refresh user list
            self.refresh_user_list()
            self.read_messages()
            self.root.update()
            
            print("\n=== Main screen setup complete ===\n")
            
        except Exception as e:
            print(f"\n!!! Error setting up main screen: {str(e)} !!!\n")
            import traceback
            traceback.print_exc()
    
    def handle_login(self):
        print("\n=== Login/Signup Attempt ===\n")
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_label.config(text="Please enter both username and password")
            return
            
        print(f"Username entered: {username}")
        hashed_password = hash_password(password)
        print(f"Password hashed for {username}")
        
        # Check if user exists
        print(f"Looking up user object for username: {username}")
        user = get_user_by_username(username)
        print(f"User lookup result: {user}")
        
        # Handle non-existent user
        if not user:
            print(f"\n=== User Not Found Flow ===\n")
            print(f"1. Detected missing user: {username}")
            
            # Show account creation dialog
            try:
                print("2. Showing account creation dialog...")
                should_create = messagebox.askyesno(
                    "Create New Account",
                    f"User '{username}' does not exist. Would you like to create a new account?",
                    icon='question',
                    parent=self.root
                )
                
                if not should_create:
                    print("3. User declined account creation")
                    self.error_label.config(text="Login canceled - user doesn't exist")
                    return
                
                print("3. Creating new account...")
                try:
                    self.current_token = create_account(username, hashed_password)
                    user = get_user_by_username(username)
                    if not user:
                        raise Exception("Failed to create account")
                    
                    self.current_user_id = user.userID
                    print("4. Account created successfully")
                    messagebox.showinfo(
                        "Welcome",
                        f"Welcome {username}! Your account has been created.",
                        parent=self.root
                    )
                    self.show_main_screen()
                    return
                    
                except Exception as e:
                    print(f"ERROR: Failed to create account: {e}")
                    self.error_label.config(text=f"Account creation failed: {str(e)}")
                    return
                    
            except Exception as e:
                print(f"ERROR: Dialog failed: {e}")
                self.error_label.config(text="Failed to create account")
                return
        
        # Handle existing user login
        try:
            print("\n=== Existing User Login Flow ===\n")
            self.current_token = check_password(username, hashed_password)
            self.current_user_id = user.userID
            print("Login successful")
            self.show_main_screen()
            messagebox.showinfo(
                "Welcome Back",
                f"Welcome back, {username}!",
                parent=self.root
            )
        except AssertionError:
            print("ERROR: Invalid password")
            self.error_label.config(text="Invalid password")
        except Exception as e:
            print(f"ERROR: Login failed: {e}")
            self.error_label.config(text=f"Login failed: {str(e)}")
    
    def handle_signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        try:
            hashed_password = hash_password(password)
            self.current_token = create_account(username, hashed_password)
            user = user_trie.trie.get(username)
            self.current_user_id = user.uid
            self.show_main_screen()
        except AssertionError:
            messagebox.showerror("Error", "Username already exists")
    
    def handle_logout(self):
        self.current_user_id = None
        self.current_token = None
        self.show_login_screen()
        
    def create_user_list(self):
        """Creates the left panel containing the list of online users"""
        # Frame for user list with fixed width
        users_frame = ttk.Frame(self.main_frame, width=200)
        users_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        users_frame.grid_propagate(False)  # Maintain fixed width
        
        # Label above user list
        ttk.Label(users_frame, text="Available Users", font=("Helvetica", 10, "bold")).grid(row=0, column=0, pady=5)
        
        # Listbox for users with scrollbar
        self.users_list = tk.Listbox(users_frame, selectmode=tk.SINGLE, font=("Helvetica", 10))
        users_scrollbar = ttk.Scrollbar(users_frame, orient=tk.VERTICAL, 
                                      command=self.users_list.yview)
        self.users_list.configure(yscrollcommand=users_scrollbar.set)
        
        # Bind selection event
        self.users_list.bind('<<ListboxSelect>>', self.on_user_select)
        
        # Grid the listbox and scrollbar
        self.users_list.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        users_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Selected user label
        self.selected_user_label = ttk.Label(users_frame, text="No user selected", font=("Helvetica", 9))
        self.selected_user_label.grid(row=2, column=0, pady=5)
        
        # Configure grid weights
        users_frame.columnconfigure(0, weight=1)
        users_frame.rowconfigure(1, weight=1)

    def create_message_area(self):
        """Creates the center panel containing the message history"""
        # Frame for messages
        messages_frame = ttk.Frame(self.main_frame)
        messages_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Message controls frame
        controls_frame = ttk.Frame(messages_frame)
        controls_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Refresh and Delete buttons
        ttk.Button(controls_frame, text="Refresh Messages", command=self.read_messages).grid(row=0, column=0, padx=5)
        ttk.Button(controls_frame, text="Delete Selected", command=self.delete_selected_messages).grid(row=0, column=1, padx=5)
        
        # Label for messages
        ttk.Label(messages_frame, text="Messages", font=("Helvetica", 10, "bold")).grid(row=1, column=0, pady=5)
        
        # Listbox for messages with scrollbar
        self.messages_list = tk.Listbox(messages_frame, selectmode=tk.MULTIPLE, font=("Helvetica", 10))
        messages_scrollbar = ttk.Scrollbar(messages_frame, orient=tk.VERTICAL,
                                         command=self.messages_list.yview)
        self.messages_list.configure(yscrollcommand=messages_scrollbar.set)
        
        # Grid the listbox and scrollbar
        self.messages_list.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        messages_scrollbar.grid(row=2, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        messages_frame.columnconfigure(0, weight=1)
        messages_frame.rowconfigure(2, weight=1)

    def create_input_area(self):
        """Creates the bottom panel containing the message input and send button"""
        # Frame for input area
        input_frame = ttk.Frame(self.main_frame)
        input_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=10)
        
        # Message entry field
        self.message_entry = ttk.Entry(input_frame, font=("Helvetica", 10))
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        
        # Send button
        self.send_button = ttk.Button(input_frame, text="Send",
                                    command=self.send_message)
        self.send_button.grid(row=0, column=1, sticky=(tk.E), padx=5)
        
        # Configure grid weights
        input_frame.columnconfigure(0, weight=1)
        
        # Bind Enter key to send message
        self.message_entry.bind("<Return>", lambda e: self.send_message())
    def handle_signup(self):
        """Handle signup button click"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_label.config(text="Please enter both username and password")
            return
        
        try:
            # Hash the password and create account
            hashed_password = hash_password(password)
            create_account(username, hashed_password)
            
            # Auto-login after successful signup
            self.handle_login()
        except AssertionError:
            self.error_label.config(text="Username already exists")
        except Exception as e:
            self.error_label.config(text=str(e))
    
    def handle_logout(self):
        """Handle logout button click"""
        self.current_user_id = None
        self.current_token = None
        self.show_login_screen()
    
    def refresh_user_list(self):
        """Refresh the list of available users"""
        print("\n=== Refreshing user list... ===\n")
        try:
            print("1. Clearing user list...")
            self.users_list.delete(0, tk.END)
            
            print("2. Getting current username...")
            current_username = get_username_by_id(self.current_user_id)
            print(f"Current username: {current_username}")
            
            print("3. Getting all users...")
            users = list_accounts("*")
            print(f"Found {len(users)} users: {users}")
            
            print("4. Adding users to list...")
            for username in users:
                if username != current_username:
                    self.users_list.insert(tk.END, username)
                    print(f"Added user: {username}")
            
            print("\n=== User list refresh complete ===\n")
        except Exception as e:
            print(f"\n!!! Error refreshing user list: {str(e)} !!!\n")
            import traceback
            traceback.print_exc()
    
    def send_message(self):
        """Send a message to the selected user"""
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Get selected recipient
        selection = self.users_list.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a recipient")
            return
        
        recipient_username = self.users_list.get(selection[0])
        recipient = get_user_by_username(recipient_username)
        if not recipient:
            messagebox.showerror("Error", "Recipient does not exist")
            return
        recipient_id = recipient.userID  # Get the recipient's user ID
    
        # Send the message
        if send_message(self.current_user_id, recipient_id, message):
            self.message_entry.delete(0, tk.END)
            self.read_messages()
        else:
            messagebox.showerror("Error", "Failed to send message")
    
    def read_messages(self):
        """Read and display messages"""
        print("Refreshing messages...")
        self.messages_list.delete(0, tk.END)
        self.message_ids.clear()
        
        # Get selected user
        selection = self.users_list.curselection()
        if not selection:
            self.messages_list.insert(tk.END, "Select a user to view messages")
            return
            
        selected_username = self.users_list.get(selection[0])
        selected_user = get_user_by_username(selected_username)
        if not selected_user:
            return
            
        # Get all messages between current user and selected user
        conversation_key = tuple(sorted([self.current_user_id, selected_user.userID]))
        if conversation_key not in conversations.conversations:
            self.messages_list.insert(tk.END, f"No messages with {selected_username} yet")
            return
            
        messages = conversations.conversations[conversation_key]
        messages.sort(key=lambda x: x.uid)  # Sort by message ID to maintain order
        
        # Display messages
        for msg in messages:
            if msg.sender_id == self.current_user_id:
                display_text = f"You: {msg.contents}"
            else:
                sender_username = get_username_by_id(msg.sender_id)
                if not msg.has_been_read:
                    display_text = f"[NEW] {sender_username}: {msg.contents}"
                else:
                    display_text = f"{sender_username}: {msg.contents}"
                    
            self.messages_list.insert(tk.END, display_text)
            self.message_ids.append(msg.uid)
            
        # Mark all messages from this conversation as read
        for msg in messages:
            if not msg.has_been_read and msg.receiver_id == self.current_user_id:
                read_messages(self.current_user_id, 1)  # Mark one message at a time
        
        # Scroll to bottom
        self.messages_list.see(tk.END)
    
    def delete_selected_messages(self):
        """Delete selected messages"""
        selection = self.messages_list.curselection()
        if not selection:
            return
        
        # Delete selected messages
        for index in reversed(selection):
            message_id = self.message_ids[index]
            if delete_message(self.current_user_id, message_id):
                self.messages_list.delete(index)
                del self.message_ids[index]
    
    def on_user_select(self, event):
        """Handle user selection from the list"""
        selection = self.users_list.curselection()
        if not selection:
            self.selected_user_label.config(text="No user selected")
            return
            
        selected_username = self.users_list.get(selection[0])
        self.selected_user_label.config(text=f"Selected: {selected_username}")
        
        # Update message display to show conversation with selected user
        self.read_messages()
    
    def run(self):
        """Start the main event loop"""
        # Create test users
        test_users = [
            ("alice", "test123"),
            ("bob", "test123"),
            ("charlie", "test123"),
            ("david", "test123"),
            ("eve", "test123")
        ]
        
        # Create test account users
        for username, password in test_users:
            try:
                if not user_trie.trie.get(username):
                    create_account(username, hash_password(password))
            except Exception as e:
                print(f"Error creating user {username}: {e}")
        
        # Print test accounts
        print("Test accounts created:")
        for username, password in test_users:
            print(f"Username: {username}, Password: {password}")
        
        # Start the main loop
        self.root.mainloop()

if __name__ == "__main__":
    # Create and run the chat interface
    chat = ChatInterface()
    chat.run()
