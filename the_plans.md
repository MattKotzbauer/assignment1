
(I'd recommend viewing in raw markdown rather than GH markdown preview)

**High-Level Details:**

- Primary Entities:
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
  hashedPassword
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
   - GlobalSessionTokens
     - (Hashmap: userID -> session token)
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
   (a) repeat this cycle for the number of new messages within unreadMessages:
       * take the most recent new message, and mark it as 'has been read'
       	 * (this will allow the user to see it in th GUI)
	 
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



1. Enter username
	1. Request (0x01)
		1. length (4 bytes)
		2. 0x01
		3. username length (2 bytes)
		4. username
	2. Response (0x02)
		1. status code (1 byte)
			1. 0x00 (name untaken, send 0x03 request), 0x01 (name taken, send 0x05 request)
2. Create account
	1. Request (0x03)
		1. length (2 bytes)
		2. 0x03
		3. username length (2 bytes)
		4. username
		5. hashed password (32 bytes)
	2. Response (0x04)
		1. length
		2. 0x04
		3. session token (32 bytes)
3. Log into account
	1. Request (0x05)
		1. length
		2. 0x05
		3. username length
		4. username
		5. hashed password (32 bytes)
	2. Response (0x06)
		1. length
		2. 0x06
		3. status code (1 byte)
			1. 0x00 (success)
			2. 0x01 (invalid credentials)
		4. session token (16 bytes)
		5. unread messages count (4 bytes)
4. Log out of account
	1. Request (0x07)
		1. length
		2. 0x07
		3. user id (2 bytes)
		4. session token (16 bytes)
	2. Response (0x08)
		1. length
		2. 0x08
5. List accounts
	1. Request (0x9)
		1. length
		2. 0x09
		3. session token (16 bytes)
		4. wildcard length (1 byte)
		5. wildcard string
	2. Response (0x10)
		1. length
		2. 0x10
		3. count of accounts (2 bytes)
			1. for the length of count:
				1. username length (1 byte)
				2. username
6. Display conversation
	1. Request (0x11)
		1. length
		2. 0x11
		3. session token (16 bytes)
		4. user ID (2 bytes)
		5. conversant user ID (2 bytes)
	2. Response (0x12)
		1. length 
		2. 0x12
		3. count of messages (4 bytes)
			1. for the length of count: 
				1. message length (1 byte)
				2. recipient / sender (1 byte)
					1. 0x00: recipient, 0x01: sender
				3. message content (string)
7. Send message 
	1. Request (0x13)
		1. length
		2. 0x13
		3. user ID (2 bytes)
		4. recipient ID (2 bytes)
		5. session token (16 bytes)
		6. message length (4 bytes)
		7. message content
	2. Response (0x14)
		1. length
		2. 0x14
8. Read messages
	1. Request (0x15)
		1. length
		2. 0x15
		3. session token (16 bytes)
		4. number of desired messages (4 bytes)
	2. Response (0x16)
		1. length
		2. 0x16
9. Delete message
	1. Request (0x17)
		1. length
		2. 0x17
		3. user ID (2 bytes)
		4. message UID (4 bytes)
		5. session token (16 bytes)
	2. Response (0x18)
		1. length
		2. 0x18
10. Delete account
	1. Request (0x19)
		1. length
		2. 0x19
		3. userID
		4. session token (16 bytes)
	2. Response (0x20)
		1. length
		2. 0x20

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
 
