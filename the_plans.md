
(I'd recommend viewing in raw markdown rather than GH markdown preview)

**High-Level Details:**

- Base Data:
  - **Messages**
    - Single message between users
  - **Users**
    - Single chat conversant

Message{
  UID
     * (distinct int)
  contents
     * (string)
  senderID
     * (int correseponding to userID of sender)
  receiverID
     * (int corresponding to userID of receiver)
  hasBeenRead
     * (bool)
  timestamp
     * (Unix format)
}


User{
  userID
     * (distinct int)
  username
     * (string)
  passwordHash
     * (string)
     * (64-character hexadecimal string from sha256.hexdigest())
  unreadMessages
     * queue of message UID's (deque)
       * TODO: decide data structure by which to store queue. DLL should suffice? (We pop from the start, and insert not far from the end)
  recentConversants
     * (a list of userID's in the order of message recency, for showing messages on the GUI and deleting conversations on deleted account)
}


- Data Structures:
  - **Users**: 
    - GlobalUserBase
      - Hashmap: userID -> User (more specifically, reference to User class instance)
    - GlobalUserTrie
      - (Trie: Ternary Search Tree)
      	- (needs to support: regex lookup for '*' (any sequence) and '?' (any single character), deletion)
	- (key: username, value: User)
	- (design fallback: change value to userID)
	- (contained in `base_trie_implementation.py`)
 - **Messages**:
    - GlobalMessageBase
      - Hashmap (UID -> Message)
    - GlobalConversations
      - Hashmap ((userID1, userID2) tuple -> list of Message instance handles)
      	- (design fallback: change value to Message UID)

  

Operations:
1. Create account
   - Inputs: username, password (hashed)
   (a) search GlobalUserTrie for username
      (i.) if username does not exist: create new account
      	   (a) generate new unique userID
   	   (b) create instance of User class using metadata
   	   (c) (generate session token, register on backend, and send back to client)
     (ii.) (if username already exists: prompt user to log in)
2. Log into account
   - Inputs: username, password (hashed)
   (a) search GlobalUserTrie for username to get user data
   (b) validate password against existing entry for GlobalUserBase[userID]
   (c.i.) if password is valid: generate session token, register on backend, and send back to client
   (c.ii.) (if password is not valid: send back error message)
3. List accounts
   - Input: search term (username or wildcard regex)
   (a) search trie and return list of relevant userID's
   (b) use userID's 
4. Send message
   - Inputs: message content, receiverID
   (a) create new instance of Message class containing message content and receiverID
   (b) add new message to GlobalConversations[(userID1, userID2)]
   (c.i.) if receiver is logged in: set hasBeenRead to true, allowing receiver to view it in GUI
   (c.ii.) if receiver is not logged in: set hasBeenRead to false and add Message UID to receiver's unreadMessages queue
5. Read messages
   - Input: number of new messages to be read
6.a. Delete message
   - Input: UID of Message instance
   (a) remove from GlobalMessageBase
   (b) if unread, remove from receiver's unreadMessages
   (c) remove corresponding entry from GlobalConversations
6.b. Delete conversation
   - Input: (userID1, userID2)
   (a) go through all messages in GlobalConversations[(userID1, userID2)]. Delete each message using (6.a.)
       * (note that deletion from GlobalConversations can be batched into step (b))
   (b) delete entry in GlobalConversations
7. Delete account
   - Input: userID
   (a) delete account from GlobalUserTrie
   (b) go through user's recentConversants, and using the (userID1, userID2) pairs as keys, delete all conversations using (6.b.)


---
**Wire Protocol:**

Packet Form: 
- Length (2 bytes)
	- `[ Length (2 bytes) | Message Type (1 byte) | Session Token (16 bytes) | Payload (...) ]`
- Message type (1 byte)
	- `0x01: Create Account Request 0x02: Create Account Response 0x03: Login Request 0x04: Login Response 0x05: List Accounts Request 0x06: List Accounts Response 0x07: Send Message Request 0x08: Send Message Response 0x09: Read Messages Request 0x0A: Read Messages Response 0x0B: Delete Messages Request 0x0C: Delete Messages Response 0x0D: Delete Account Request 0x0E: Delete Account Response`
- Session token (16 bytes)
- Payload (sz - 19 bytes)


General Transaction Format:
Client sends (Create account / Login) packet to server
* (salt + hash password before sending it over the wire)
Server sends session token to client
Client uses session token for all message API requests (read, send message, search for accounts, delete message, delete account
)

Old Format (TODO: refine for new types):
```
CREATE ACCOUNT:
Request (0x01)
[ Length | 0x01 | username_length (1 byte) | username | password_hash (32 bytes) ]
Response (0x02)
[ Length | 0x02 | status_code (1 byte) | session_token (16 bytes) ]
Status codes: 0x00 (success), 0x01 (name taken), 0x02 (invalid name)

LOGIN:
Request (0x03)
[ Length | 0x03 | username_length (1 byte) | username | password_hash (32 bytes) ]
Response (0x04)
[ Length | 0x04 | status_code (1 byte) | session_token (16 bytes) | unread_count (4 bytes) ]
Status codes: 0x00 (success), 0x01 (invalid credentials)

LIST ACCOUNTS:
Request (0x05)
[ Length | 0x05 | pattern_length (1 byte) | pattern | offset (4 bytes) | limit (2 bytes) ]
Response (0x06)
[ Length | 0x06 | count (2 bytes) | total_matches (4 bytes) | username_entries[] ]
Username entry: [ length (1 byte) | username ]

SEND MESSAGE:
Request (0x07)
[ Length | 0x07 | recipient_length (1 byte) | recipient | message_length (2 bytes) | message ]
Response (0x08)
[ Length | 0x08 | status_code (1 byte) | message_id (8 bytes) ]
Status codes: 0x00 (delivered), 0x01 (queued), 0x02 (user not found)

READ MESSAGES:
Request (0x09)
[ Length | 0x09 | max_messages (2 bytes) ]
Response (0x0A)
[ Length | 0x0A | message_count (2 bytes) | messages[] ]
Message: [ message_id (8 bytes) | sender_length (1 byte) | sender | message_length (2 bytes) | message ]

DELETE MESSAGES:
Request (0x0B)
[ Length | 0x0B | message_count (2 bytes) | message_ids[] ]
Message_ids: [ message_id (8 bytes) ]
Response (0x0C)
[ Length | 0x0C | status_code (1 byte) | deleted_count (2 bytes) ]

DELETE ACCOUNT:
Request (0x0D)
[ Length | 0x0D | password_hash (32 bytes) ]
Response (0x0E)
[ Length | 0x0E | status_code (1 byte) ]
Status codes: 0x00 (success), 0x01 (auth failed)
```


TODO's:
* refine Wire Protocol to reflect new types / data structures
  * (Create account, login should be accurate)
* define session token data structure
  * (We could have it such that after 30 minutes, a new session token is sent to the client, which is then required for future queries)
  * (Needed metadata: userID, session token, time elapsed)
  * (Could keep like an auxiliary global dict for managing session tokens? E.g. userID -> member of session token class, which could contain both the token itself + valid time remaining. Then if it hits 0, we generate a new one and send it to the user)


Potential Optimizations:
* DLL + Hashmap data structure
  * Use DLL + Hashmap for conversation between users rather than a list (faster deletion)
  * Use DLL + Hashmap for recentConversants rather than a list
  * Use DLL + Hashmap for unreadMessages
 
