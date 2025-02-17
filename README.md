# CS2620 Problem Set 1: Chat Application + Custom Wire Protocol

**Engineering Notebook**: Contained in `engineering_notebook_final.md`
**Implementation Files**: Contained in `client/` and `server/` directories, with `client/socket_handler.py` and `server/socket_handler.py` being their respective entry points
**High-Level Documentation + Usage Instructions**: Contained below!

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

Host the server: 
```bash
python server/socket_handler.py {IP} {PORT}
```

Run the GUI client: 
```bash
python client/tkinter_base.py {IP} {PORT}
```

Make sure that the IP and Port you connect to from the client match those of the server. To run locally on a machine, '127.0.0.1' or 'localhost' can be specified as an IP address. To run on multiple machines, the server's IP address must match the actual IP address of the machine running the server, and both machines need to be on the same network. Choosing a port above 1024 helps to avoid the necessary admin priveleges that the lower ports often require (with the maximum valid port number being 65535). 

Simulate a client using Python: 
```python
# (Within client.py directory)
import client
sample_client = Client(host = '127.0.0.1', port = 65432)
client.connect()
# (API calls can the be accessed with client.{function_name})
```

Run the application:
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
├── server/                     # Server-side
│   └── socket_handler.py       # Server socket management and message handling
│
├── client/                     # Client-side 
│   └── socket_handler.py       # Client socket management and message handling
│
├── auxiliary_data_structures/  # Helper data structures
│   └── ...                     # Utility classes and functions; helpers
│
├── driver/                     # Main application logic
│   ├── message_driver.py       # Message handling and routing
│   ├── user_driver.py          # User management and authentication
│   └── ...                     # Other functionality
│
├── tkinter_base.py            # GUI implementation using Tkinter
├── test_tkinter_base.py       # GUI unit tests
├── design_notebook.md         # Design decisions and implementation notes
└── the_plans.md               # Project planning and requirements
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
