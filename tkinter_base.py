import tkinter as tk
from tkinter import ttk
import threading
from queue import Queue

class ChatInterface:
    def __init__(self):
        # Initialize the main window
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("800x600")  # Set a reasonable default size
        
        # Message queue for thread-safe communication
        self.message_queue = Queue()
        
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
        
    def create_user_list(self):
        """Creates the left panel containing the list of online users"""
        # Frame for user list with fixed width
        users_frame = ttk.Frame(self.main_frame, width=200)
        users_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        users_frame.grid_propagate(False)  # Maintain fixed width
        
        # Label above user list
        ttk.Label(users_frame, text="Online Users").grid(row=0, column=0, pady=5)
        
        # Listbox for users with scrollbar
        self.users_list = tk.Listbox(users_frame)
        users_scrollbar = ttk.Scrollbar(users_frame, orient=tk.VERTICAL, 
                                      command=self.users_list.yview)
        self.users_list.configure(yscrollcommand=users_scrollbar.set)
        
        # Grid the listbox and scrollbar
        self.users_list.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        users_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        users_frame.columnconfigure(0, weight=1)
        users_frame.rowconfigure(1, weight=1)

    def create_message_area(self):
        """Creates the center panel containing the message history"""
        # Frame for messages
        messages_frame = ttk.Frame(self.main_frame)
        messages_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Text widget for messages with scrollbar
        self.messages_text = tk.Text(messages_frame, wrap=tk.WORD, state='disabled')
        messages_scrollbar = ttk.Scrollbar(messages_frame, orient=tk.VERTICAL,
                                         command=self.messages_text.yview)
        self.messages_text.configure(yscrollcommand=messages_scrollbar.set)
        
        # Grid the text widget and scrollbar
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        messages_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        messages_frame.columnconfigure(0, weight=1)
        messages_frame.rowconfigure(0, weight=1)

    def create_input_area(self):
        """Creates the bottom panel containing the message input and send button"""
        # Frame for input area
        input_frame = ttk.Frame(self.main_frame)
        input_frame.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        # Message entry field
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        # Send button
        self.send_button = ttk.Button(input_frame, text="Send",
                                    command=self.send_message)
        self.send_button.grid(row=0, column=1, sticky=(tk.E))
        
        # Configure grid weights
        input_frame.columnconfigure(0, weight=1)
        
        # Bind Enter key to send message
        self.message_entry.bind("<Return>", lambda e: self.send_message())

    def send_message(self):
        """Handler for sending messages (placeholder for now)"""
        message = self.message_entry.get()
        if message:
            # Clear the input field
            self.message_entry.delete(0, tk.END)
            
            # In the future, this will send the message to the server
            # For now, just echo it to the message area
            self.display_message(f"You: {message}")

    def display_message(self, message):
        """Adds a message to the message area"""
        self.messages_text.configure(state='normal')
        self.messages_text.insert(tk.END, message + '\n')
        self.messages_text.configure(state='disabled')
        self.messages_text.see(tk.END)  # Scroll to bottom

    def run(self):
        """Starts the main event loop"""
        self.root.mainloop()

if __name__ == "__main__":
    # Create and run the chat interface
    chat = ChatInterface()
    chat.run()
