

**High-Level Details:**

Design:
- Data Structures:
  - User Accounts: Trie
    - (Ternary search tree)
      - (We need to be able to do a regex lookup with '*' for any sequence of characters, '?' for any single character)
      - (We need to be able to delete an account, e.g. delete a string from the Trie)
  - Messages: Hashmap
    - (We need to have O(1) insertions / deletions given a UID)

Message{
  UID
     * (distinct int)
  contents
     * (string)
  senderID
     * (int correseponding to userID of sender)
  receiverID
     * (int correspondingt to userID of receiver)
  hasBeenRead
     * (bool)
  timestamp
     * (?? idk the format)
}

User{
  userID
     * (distinct int)
  unreadMessages
     * queue of message UID's
       * (could alternatively use pointers)
       * TODO: decide data structure by which to store queue. DLL should suffice? (We pop from the start, and insert not far from the end)
  conversations
     * hashmap from a userID (the other user in the chat) to a list of message UID's
       * (could alternatively use pointers)
       * (we could potentially have a common list between the sender and receiver, as their lists will be identical. Python may do this implicitly depending on how we populate it, e.g. populating with a mutable data structure will give a pointer to the structure)
       * TODO: decide data structure by which 'list of messages' is stored: AVL tree should suffice
}

Note that when a message is deleted, this means that we must remove it from:
* the sender's conversations
* the receiver's conversations
* the receiver's unreadMessages (if it still exists there, e.g. if GlobalMessages[UID].hasBeenRead = False)
* our global GlobalMessages dict

Sending a message:
* creates a new instance of Message class
* populates sender and receiver's list in 'conversations' with the message
* if receiver is logged in:
  * set hasBeenRead to true, allowing receiver to view it
* if receiver isn't logged in:
  * set hasBeenRead to false and add to receiver's unreadMessages queue

Ordering messages:
* use Unix timestamp of server
* if we let our server process messages in the order that it receives them, it will implicitly sort by timestamp
  * for a further guarantee, can insert messages into the queue of unreadMessages / the list of messages for the user's conversation in the order they were received




---
**Wire Protocol:**

Packet Form: 
- Length (2 bytes)
	- `[ Length (2 bytes) | Message Type (1 byte) | Session Token (16 bytes) | Payload (...) ]`
- Message type (1 byte)
	- `0x01: Create Account Request 0x02: Create Account Response 0x03: Login Request 0x04: Login Response 0x05: List Accounts Request 0x06: List Accounts Response 0x07: Send Message Request 0x08: Send Message Response 0x09: Read Messages Request 0x0A: Read Messages Response 0x0B: Delete Messages Request 0x0C: Delete Messages Response 0x0D: Delete Account Request 0x0E: Delete Account Response`
- Session token (16 bytes)
- Payload (sz - 19 bytes)

```
CREATE ACCOUNT:
Request (0x01)
[ Length | 0x01 | username_length (1 byte) | username | password_hash (32 bytes) ]
Response (0x02)
[ Length | 0x02 | status_code (1 byte) ]
Status codes: 0x00 (success), 0x01 (name taken), 0x02 (invalid name)

LOGIN:
Request (0x03)
[ Length | 0x03 | username_length (1 byte) | username | password_hash (32 bytes) ]
Response (0x04)
[ Length | 0x04 | status_code (1 byte) | unread_count (4 bytes) ]
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


