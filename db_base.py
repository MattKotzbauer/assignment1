class Message:
    def __init__(self, content, sender, recipient, timestamp):
        self.content = content
        self.sender = sender
        self.recipient = recipient
        self.timestamp = timestamp
        self.next = None
        self.prev = None

class MessageStore:
    def __init__(self):
        self.uid_to_message = {}  # HashMap for O(1) lookup/deletion
        self.head = None          # Start of linked list
        
    def insert(self, uid, message):
        # Add to HashMap
        self.uid_to_message[uid] = message
        
        # Add to front of linked list
        if self.head:
            message.next = self.head
            self.head.prev = message
        self.head = message
            
    def get(self, uid):
        return self.uid_to_message.get(uid)
    
    def delete(self, uid):
        if uid not in self.uid_to_message:
            return False
            
        message = self.uid_to_message[uid]
        
        # Remove from HashMap
        del self.uid_to_message[uid]
        
        # Remove from linked list
        if message.prev:
            message.prev.next = message.next
        else:  # If this was the head
            self.head = message.next
            
        if message.next:
            message.next.prev = message.prev
            
        return True
        
    def get_latest_messages(self, limit=10):
        """Traverse from head to get latest messages"""
        result = []
        current = self.head
        while current and len(result) < limit:
            result.append(current)
            current = current.next
        return result

    def update(self, uid, new_content):
    """Update message content while preserving its position and metadata"""
    if uid not in self.uid_to_message:
        return False
    
    message = self.uid_to_message[uid]
    message.content = new_content
    return True

    

    
