import unittest
from unittest.mock import MagicMock, patch
from collections import namedtuple
import tkinter as tk
from tkinter_base import ChatInterface, get_username_by_id, get_user_by_username
from server.core_entities import User, Message

class TestChatInterface(unittest.TestCase):
    def setUp(self):
        self.chat = ChatInterface()
        self.chat.root.withdraw()

    def tearDown(self):
        self.chat.root.destroy()

    @patch('tkinter_base.get_user_by_username')
    @patch('tkinter_base.hash_password')
    @patch('tkinter_base.check_password')
    def test_handle_login_existing_user(self, mock_check_password, mock_hash_password, mock_get_user):
        """Test login functionality for existing user"""
        # Setup mocks
        test_username = "testuser"
        test_password = "password123"
        test_hash = "hashed_password"
        test_token = "test_token"
        test_user = MagicMock(spec=User)
        test_user.userID = 1
        
        mock_hash_password.return_value = test_hash
        mock_get_user.return_value = test_user
        mock_check_password.return_value = test_token

        # Set up the login form
        self.chat.username_entry = MagicMock()
        self.chat.password_entry = MagicMock()
        self.chat.error_label = MagicMock()
        self.chat.username_entry.get.return_value = test_username
        self.chat.password_entry.get.return_value = test_password

        self.chat.show_main_screen = MagicMock()

        # Test login
        self.chat.handle_login()

        # verify login process
        mock_hash_password.assert_called_once_with(test_password)
        mock_get_user.assert_called_once_with(test_username)
        mock_check_password.assert_called_once_with(test_username, test_hash)
        self.assertEqual(self.chat.current_user_id, test_user.userID)
        self.assertEqual(self.chat.current_token, test_token)
        self.chat.show_main_screen.assert_called_once()

    def test_handle_logout(self):
        """Test logout functionality"""
        # Set initial state
        self.chat.current_user_id = 1
        self.chat.current_token = "test_token"
        
        self.chat.show_login_screen = MagicMock()

        # Test logout
        self.chat.handle_logout()
        self.assertIsNone(self.chat.current_user_id)
        self.assertIsNone(self.chat.current_token)
        self.chat.show_login_screen.assert_called_once()

    @patch('tkinter_base.user_base')
    def test_get_username_by_id(self, mock_user_base):
        """Test getting username by user ID"""
        test_user = MagicMock(spec=User)
        test_user.username = "testuser"
        mock_user_base.users = {1: test_user}

        # Test with user
        result = get_username_by_id(1)
        self.assertEqual(result, "testuser")

        # Test with non existent user
        result = get_username_by_id(999)
        self.assertIsNone(result)

    @patch('tkinter_base.user_trie')
    def test_get_user_by_username(self, mock_user_trie):
        """Test getting user object by username"""
        test_user = MagicMock(spec=User)
        test_user.userID = 1
        mock_user_trie.trie.get.return_value = test_user

        # Test with existing username
        result = get_user_by_username("testuser")
        self.assertEqual(result, test_user)
        mock_user_trie.trie.get.assert_called_once_with("testuser")

    @patch('tkinter_base.create_account')
    @patch('tkinter_base.hash_password')
    @patch('tkinter_base.messagebox')
    @patch('tkinter_base.get_user_by_username')
    def test_handle_new_user_creation(self, mock_get_user, mock_messagebox, mock_hash_password, mock_create_account):
        """Test new user creation through login handler"""
        # Setup mocks
        test_username = "newuser"
        test_password = "password123"
        test_hash = "hashed_password"
        test_token = "test_token"
        test_user = MagicMock(spec=User)
        test_user.userID = 1
        
        # First return None to simulate new user, then return created user
        mock_get_user.side_effect = [None, test_user]
        mock_hash_password.return_value = test_hash
        mock_create_account.return_value = test_token
        mock_messagebox.askyesno.return_value = True  # User agrees to create account

        # Set up the login form
        self.chat.username_entry = MagicMock()
        self.chat.password_entry = MagicMock()
        self.chat.error_label = MagicMock()
        self.chat.username_entry.get.return_value = test_username
        self.chat.password_entry.get.return_value = test_password

        self.chat.show_main_screen = MagicMock()

        # Test new user creation
        self.chat.handle_login()

        # Verify the account creation process
        mock_hash_password.assert_called_once_with(test_password)
        mock_get_user.assert_has_calls([
            unittest.mock.call(test_username),  # First call to check if user exists
            unittest.mock.call(test_username)   # Second call after creating account
        ])
        mock_create_account.assert_called_once_with(test_username, test_hash)
        mock_messagebox.askyesno.assert_called_once()
        mock_messagebox.showinfo.assert_called_once()
        self.assertEqual(self.chat.current_user_id, test_user.userID)
        self.assertEqual(self.chat.current_token, test_token)
        self.chat.show_main_screen.assert_called_once()

        # Test with empty fields
        self.chat.username_entry.get.return_value = ""
        self.chat.handle_login()
        self.chat.error_label.config.assert_called_with(
            text="Please enter both username and password")

    @patch('tkinter_base.send_message')
    @patch('tkinter_base.get_user_by_username')
    def test_send_message(self, mock_get_user, mock_send_message):
        """Test sending a message to another user"""
        # Setup mocks
        test_recipient = MagicMock(spec=User)
        test_recipient.userID = 2
        mock_get_user.return_value = test_recipient
        mock_send_message.return_value = True
        
        # Setup chat interface
        self.chat.current_user_id = 1
        self.chat.message_entry = MagicMock()
        self.chat.messages_list = MagicMock()
        self.chat.users_list = MagicMock()
        self.chat.display_messages = MagicMock()
        
        # Setup test message
        test_message = "Hello, test user!"
        self.chat.message_entry.get.return_value = test_message
        self.chat.users_list.curselection.return_value = [0]
        self.chat.users_list.get.return_value = "testuser"
        
        # Test sending message
        self.chat.send_message()
        
        # Verify message was sent
        mock_get_user.assert_called_with("testuser")
        mock_send_message.assert_called_once_with(1, 2, test_message)
        self.chat.message_entry.delete.assert_called_once_with(0, tk.END)
        self.chat.display_messages.assert_called_once()

    @patch('tkinter_base.conversations')
    @patch('tkinter_base.get_user_by_username')
    @patch('tkinter_base.get_username_by_id')
    def test_display_messages(self, mock_get_username, mock_get_user, mock_conversations):
        """Test displaying messages between users"""
        # Setup mocks
        test_user = MagicMock(spec=User)
        test_user.userID = 2
        mock_get_user.return_value = test_user
        mock_get_username.return_value = "testuser"
        
        # Create test messages
        test_messages = [
            MagicMock(spec=Message, uid=1, sender_id=1, contents="Hello!", has_been_read=True),  # Sent by current user
            MagicMock(spec=Message, uid=2, sender_id=2, contents="Hi there!", has_been_read=False),  # Unread message from other user
            MagicMock(spec=Message, uid=3, sender_id=2, contents="How are you?", has_been_read=True),  # Read message from other user
        ]
        
        # Setup conversations mock
        mock_conversations.conversations = {(1, 2): test_messages}
        
        # Setup chat interface
        self.chat.current_user_id = 1
        self.chat.messages_list = tk.Listbox(self.chat.root)
        self.chat.message_ids = []
        self.chat.users_list = MagicMock()
        self.chat.users_list.curselection.return_value = [0]
        self.chat.users_list.get.return_value = "testuser"
        
        # Test displaying messages
        self.chat.display_messages()
        
        # Get all displayed messages
        displayed_messages = []
        for i in range(self.chat.messages_list.size()):
            msg = self.chat.messages_list.get(i)
            if not msg.startswith('━━━'):  # Skip separators
                displayed_messages.append(msg)
        
        expected_messages = [
            "testuser: Hi there!",
            "You: Hello!",
            "testuser: How are you?"
        ]
        self.assertEqual(displayed_messages, expected_messages)

    @patch('tkinter_base.list_accounts')
    @patch('tkinter_base.get_username_by_id')
    @patch('tkinter_base.user_base')
    @patch('tkinter_base.message_base')
    def test_refresh_user_list(self, mock_message_base, mock_user_base, mock_get_username, mock_list_accounts):
        """Test refreshing the list of available users"""
        # Setup mocks
        mock_get_username.side_effect = lambda x: {
            1: "currentuser",
            2: "user1",
            3: "user2"
        }.get(x)
        mock_list_accounts.return_value = ["user1", "currentuser", "user2"]
        
        # Setup current user w unread messages
        current_user = MagicMock(spec=User)
        current_user.unread_messages = [1, 2]  # Message IDs
        mock_user_base.users = {1: current_user}
        
        # Setup message base mock
        message1 = MagicMock(spec=Message)
        message1.sender_id = 2  # From user1
        message2 = MagicMock(spec=Message)
        message2.sender_id = 3  # From user2
        mock_message_base.messages = {1: message1, 2: message2}
        
        # Setup chat
        self.chat.current_user_id = 1
        self.chat.users_list = tk.Listbox(self.chat.root)
        
        self.chat.refresh_user_list()
        
        user_list = []
        for i in range(self.chat.users_list.size()):
            item = self.chat.users_list.get(i)
            if not item.startswith('━━━'):
                user_list.append(item)
        
        # Verify user list contents
        expected_list = [
            "user1 (MESSAGES: 1)",
            "user2 (MESSAGES: 1)"
        ]
        self.assertEqual(user_list, expected_list)

if __name__ == '__main__':
    unittest.main()
