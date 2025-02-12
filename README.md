# Chat Application

A Python-based chat application implementing both custom wire protocol and JSON-based communication.

## Installation

### Prerequisites
- Python 3.6 or higher
- Tkinter

#### Installing Python

**macOS:**
1. Using Homebrew:
```bash
brew install python3
```
2. Or download from [Python.org](https://www.python.org/downloads/)

**Windows:**
1. Download the installer from [Python.org](https://www.python.org/downloads/)
2. Run the installer (make sure to check "Add Python to PATH")

#### Installing Tkinter

**macOS:**
```bash
brew install python-tk
```

**Windows:**
Tkinter comes pre-installed with Python for Windows. If it's missing:
```bash
pip install tk
```

To verify installation:
```bash
python3 -c "import tkinter; tkinter._test()"
```



### Running the Application GUI

Run the GUI:
```bash
python3 tkinter_base.py
```

## Usage

1. To create a new account, simply type in your name, a password, and click the "Login" button. The system will prompt you to create a new account. You can also log in with the following test users:

```text
alice, test123
bob, test123
charlie, test123
david, test123
eve, test123
```

2. Once logged in, you can start messaging other users. You can also view the list of available users and their recent messages. Click on a user to start a conversation, and you'll be able to send them a message,

3. Once you've received a message, it will be displayed in the message window. You can also view your own messages. Unread messages will be shown at the top of the "avaliable users" list with the number of unread messages next to each user.

4. To delete messages, click on the user you want to delete messages from, select the messages you'd like to delete, and then click the "Delete Selected" button.

5. To logout, click the "Logout" button in the top-right corner of the GUI.

6. To delete an account, click the "Delete Account" button in the top-right corner of the GUI.

## Current Features

### Authentication
- User registration with username/password
- User login with existing credentials
- Secure password hashing

### Messaging
- Send messages to other users
- View message history
- Real-time message updates
- Unread message indicators

### User Interface
- List of available users
- Message display with sender information
- Unread message highlighting

## Implementation Details

### Architecture
- Client-server architecture with TCP sockets
- Tkinter-based GUI for client interface
- Asynchronous server handling multiple clients

### Wire Protocol
Two implementations are supported:
1. Custom Wire Protocol
2. JSON Protocol

### Testing
- Unit tests for GUI components
- Mock-based testing for network operations
- Test coverage for core functionality:
  - User authentication
  - Message sending/receiving
  - User list management

## Development

### Project Structure
```
./
├── client/           # Client implementation
├── server/           # Server implementation
├── test_*.py         # Test files
└── tkinter_base.py   # GUI implementation
```

### Running Tests

To run the tkinger tests:
```bash
python3 -m unittest test_tkinter_base.py -v
```

## Documents
Pre-planning in `the\_plans.md`

Main driver code in `driver/`

Tkinter GUI implementation in `tkinter_base.py`
