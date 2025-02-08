from collections import deque
from typing import Dict, List, Optional
import time
from dataclasses import dataclass
from hashlib import sha256

@dataclass
class Message:
    """Represents a chat message in the system."""
    uid: int
    contents: str
    sender_id: int
    receiver_id: int
    has_been_read: bool
    timestamp: float  # Unix timestamp from the server

class User:
    """
    Represents a user account in the chat system.
    
    Attributes:
        user_id: Unique identifier for the user
        username: User's login name
        password_hash: SHA-256 hash of the user's password
        unread_messages: Queue of message UIDs waiting to be read
        conversations: Dictionary mapping other user IDs to lists of message UIDs
    """
    def __init__(self, user_id: int, username: str, password: str):
        self.user_id = user_id
        self.username = username
        # Store password as SHA-256 hash
        self.password_hash = sha256(password.encode()).hexdigest()
        # Queue of unread message UIDs
        self.unread_messages = deque()
        # Map from other user_id to list of message UIDs in that conversation
        self.conversations: Dict[int, List[int]] = {}
        
    def verify_password(self, password: str) -> bool:
        """Verify if the provided password matches the stored hash."""
        return self.password_hash == sha256(password.encode()).hexdigest()
    
    def add_message_to_conversation(self, other_user_id: int, message_uid: int) -> None:
        """Add a message to the conversation with another user."""
        if other_user_id not in self.conversations:
            self.conversations[other_user_id] = []
        self.conversations[other_user_id].append(message_uid)
    
    def add_unread_message(self, message_uid: int) -> None:
        """Add a message to the unread queue."""
        self.unread_messages.append(message_uid)
    
    def get_unread_messages(self, count: Optional[int] = None) -> List[int]:
        """
        Get and remove up to 'count' unread message UIDs.
        If count is None, returns all unread messages.
        """
        if count is None:
            count = len(self.unread_messages)
        
        messages = []
        for _ in range(min(count, len(self.unread_messages))):
            messages.append(self.unread_messages.popleft())
        return messages
    
    def delete_message(self, message_uid: int, other_user_id: int) -> None:
        """
        Remove a message from this user's view of the conversation.
        Should be called for both sender and receiver when a message is deleted.
        """
        if other_user_id in self.conversations:
            try:
                self.conversations[other_user_id].remove(message_uid)
                # Clean up empty conversations
                if not self.conversations[other_user_id]:
                    del self.conversations[other_user_id]
            except ValueError:
                pass  # Message already deleted or not in conversation
        
        # Also remove from unread messages if present
        try:
            self.unread_messages.remove(message_uid)
        except ValueError:
            pass  # Message wasn't unread
