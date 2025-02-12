import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
from tkinter_base import ChatInterface, get_username_by_id, get_user_by_username
from server.core_entities import User

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

if __name__ == '__main__':
    unittest.main()
