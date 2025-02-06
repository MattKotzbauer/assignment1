import unittest
from datetime import datetime
from db_base import MessageStore, Message

class TestMessageStore(unittest.TestCase):
    def setUp(self):
        """Set up a fresh MessageStore before each test"""
        self.store = MessageStore()

    def test_insert_and_get(self):
        """Test basic insertion and retrieval"""
        msg = Message("Hello", "alice", "bob", datetime.now())
        self.store.insert("msg1", msg)
        
        retrieved = self.store.get("msg1")
        self.assertEqual(retrieved.content, "Hello")
        self.assertEqual(retrieved.sender, "alice")
        self.assertEqual(retrieved.recipient, "bob")

    def test_delete(self):
        """Test message deletion"""
        # Insert two messages
        msg1 = Message("First", "alice", "bob", datetime.now())
        msg2 = Message("Second", "bob", "alice", datetime.now())
        self.store.insert("msg1", msg1)
        self.store.insert("msg2", msg2)
        
        # Delete first message
        self.assertTrue(self.store.delete("msg1"))
        self.assertIsNone(self.store.get("msg1"))
        self.assertIsNotNone(self.store.get("msg2"))
        
        # Try deleting non-existent message
        self.assertFalse(self.store.delete("msg3"))

    def test_get_latest_messages(self):
        """Test retrieving latest messages"""
        # Insert messages in reverse chronological order
        messages = []
        for i in range(5):
            msg = Message(f"Message {i}", "alice", "bob", datetime.now())
            self.store.insert(f"msg{i}", msg)
            messages.append(msg)
        
        # Get latest 3 messages
        latest = self.store.get_latest_messages(3)
        self.assertEqual(len(latest), 3)
        self.assertEqual(latest[0].content, "Message 4")
        self.assertEqual(latest[2].content, "Message 2")

    def test_linked_list_integrity(self):
        """Test the integrity of the doubly-linked list after operations"""
        msg1 = Message("First", "alice", "bob", datetime.now())
        msg2 = Message("Second", "bob", "alice", datetime.now())
        msg3 = Message("Third", "alice", "bob", datetime.now())
        
        self.store.insert("msg1", msg1)
        self.store.insert("msg2", msg2)
        self.store.insert("msg3", msg3)
        
        # Check forward links
        current = self.store.head
        contents = []
        while current:
            contents.append(current.content)
            current = current.next
        self.assertEqual(contents, ["Third", "Second", "First"])
        
        # Delete middle message and check integrity
        self.store.delete("msg2")
        self.assertEqual(msg1.prev, msg3)
        self.assertEqual(msg3.next, msg1)

if __name__ == '__main__':
    unittest.main()
