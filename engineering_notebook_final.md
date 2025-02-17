
# Custom vs JSON Protocol Data Testing: 

These tests can be replicated by running `client/run_data_operations_test.py`. In this case, we create an instance of our Client class that bypasses the standard server-side API calls and manually defines our return type to be the amount of data within the packet. Within our set of sample queries, we found the following data measurements for our base operations: 

**Measurements:**

- **Custom Wire Protocol:**
  - `search_username`: 12 bytes
  - `create_account`: 44 bytes
  - `log_into_account`: 44 bytes
  - `log_out_of_account`: 39 bytes
  - `list_accounts`: 42 bytes
  - `display_conversation`: 41 bytes
  - `send_message`: 48 bytes
  - `read_messages`: 43 bytes
  - `delete_message`: 43 bytes
  - `delete_account`: 39 bytes

- **JSON Protocol:**
  - `search_username`: 54 bytes
  - `create_account`: 140 bytes
  - `log_into_account`: 142 bytes
  - `log_out_of_account`: 135 bytes
  - `list_accounts`: 147 bytes
  - `display_conversation`: 157 bytes
  - `send_message`: 168 bytes
  - `read_messages`: 149 bytes
  - `delete_message`: 152 bytes
  - `delete_account`: 131 bytes


Through these tests, the memory-oriented merit of using our custom wire protocol is clear, ranging from being **3x - 5x more compact** than our JSON system. One could argue that an advantage of the JSON system is its simplicity: our method of casting our input fields in and out of dictionaries is far easier than building out new functionality for the wire protocol, where we specify the size and type of each field so that we can pass in our raw data without padding. But the advantage of this system with respect to memory savings is clear, and would be especially advantageous if we were processing a lot of packets at once and / or challenging the bandwidth of our network connection. 

On the other hand, as was discussed in lecture, modern networks tend to support extremely high bandwidth, with latency being the only point that we're unable to make faster (e.g. the speed of light / electricity). In this, our packet sizes (all of which are below 1KB), combined with the scale of our chat application in-practice (using across a few machines at most) lack a tangible effect on our application with respect to its real-time latency. Unless our chat application scales to very high usage relative to this, packet choice likely wouldn't result in any tangibly visible effects for the end-user. **However**, as the application scales, these changes in memory usage mean that (irrespective of the time complexity of sending / receiving these packet), we would be able to at least support and store 3 - 5x more data before the bandwidth of our communication starts to clog our sever. This is a huge difference in scalability! Even though it's not visible in the use case of a demonstration, we'd want to use the custom protocol if we were supporting a larger user base in practice.

I'll also note a more abstract benefit of the custom protocol that's reflected in this compactness: it's **significantly** cleaner from an engineering perspective: every byte in our request and response packets is placed there deliberately, and even if we could theoretically make the packet smaller with further optimizations, it's a way of transmitting our data that does not contain excess fluff or assumptions about what we need. For this reason, the custom protocol seems stronger from a design perspective as well.


# Engineering Notebook / Build Log: 

---

## 02/05/2025 — Refining Data Models & Wire Protocol

**Thought Process:**
- In building this system, we see our first priority as establishing a set of underlying classes that we can phrase our operations in terms of 
- We arrived at a solution of categorizing our data in terms of 'Users' and 'Messages', where the former represents the current session and relationships of the user logging in, and the latter is the content of the messages they send, view, and delete
- Within these, we feel that for both Users and Messages, we want a hashmap routing their unique ID to their metadata. Further, a Trie could be useful for quickly searching usernames, while an additional conversation-based mapping system could be useful for quickly accessing conversation results
- The first-priority deliverable is to set up these underlying server-side data structures that we can call to concisely handle any functions that we want to call client-side

**Focus:**
- Refined our data models based on initial designs.
- Laid out the preliminary structure for the wire protocol.

**Data Models:**

- **Messages:**
  - **Schema:**
    - `UID` (distinct integer)
    - `contents` (string)
    - `senderID` (int; corresponds to sender's userID)
    - `receiverID` (int; corresponds to receiver's userID)
    - `hasBeenRead` (bool)
    - `timestamp` (Unix format)
  - **Purpose:** Maintain unique identification, ordering, and status (read/unread).

- **Users:**
  - **Schema:**
    - `userID` (distinct integer)
    - `username` (string)
    - `hashedPassword` (64-character hexadecimal string from SHA-256)
    - `unreadMessages` (queue of message UIDs; considering deque/DLL for efficient pops/inserts)
    - `recentConversants` (list of userIDs ordered by message recency)
  - **Global Structures:**
    - **GlobalUserBase:** Hashmap mapping `userID` → `User` instance.
    - **GlobalUserTrie:** Ternary search tree (supports regex wildcards `*` and `?`) for username lookup.
    - **GlobalMessageBase:** Hashmap mapping `UID` → `Message` instance.
    - **GlobalConversations:** Hashmap mapping `(userID1, userID2)` → list (or DLL) of messages.

**Wire Protocol (Initial Outline):**

- **Packet Structure:**
  - **Header:** 
    - 2 bytes: Total packet length.
    - 1 byte: Message type.
    - 16 bytes: Session token.
  - **Payload:** Varies by operation.

- **Operations Covered:**
  - Create Account, Log In, List Accounts, Send Message, Read Messages, Delete Message, Delete Account.
  - Each operation will have defined request and response types (e.g., `0x01`–`0x0E`).

---

## 02/06/2025 — Client-Server Session Management

**Thought Process:**
- Now that we have reasonable confidence on the structure of our server-side structures and primitives, the next most important thing is to engineer a strong way to encode a client session with the server
- This session can likely be accurately modeled as (A) a state in which the client is not logged in (where we test their provided information against our stored data to see if we grant them a session token), and (B) a state in which they are (where we test for their session token to create backend API calls)
- Our desire to support the latter motivates the distribution and usage of session tokens, which are bittersweet in that having a properly-sized hash will make our wire protocol a lot bigger (16 bytes), but will add a good degree of certainty that we're interacting with the user themselves upon their verification
  - More concretely, a mapping from user ID to session token on the server-side would allow us to verify in O(1) that we're interacting with the user themselves

**Focus:**
- Design system of verifying users (ended up adopting a session token / state management type of structure)
- Evaluate if this is sufficient security-wise

**Session Token Design:**

- **Token Structure:**
  - 16-byte tokens.
  - Encapsulate metadata: `userID`, token value, and expiration (target lifetime: 30 minutes).
- **Management:**
  - Global mapping (`GlobalSessionTokens`) from `userID` to token instance.
  - Automatic token refresh upon expiration.
  
**Security Enhancements:**

- **Password Handling:**
  - Passwords are salted and hashed using SHA-256 *before* being transmitted.
- **Protocol Integration:**
  - All subsequent requests (after login) will include the session token for authentication.
  - Future improvements include enhanced error recovery for expired tokens.

---

## 02/07/2025 — Finalizing Wire Protocol Details

**Thought Process:**
- Over the course of building our server-side structures and the connection system, we've gained an intuition for what types of messages we want to transmit
- We think that in general, this wire protocol is best represented as an immediate-mode API, wherein we can model a call a client makes to the server as a function with a typed input and output. We can then handle these calls within the wire protocol by translating these parameters into either packed bytes (for our custom wire protocol) or JSON fields (for our JSON protocol)
- We'll start by defining our wire protocol in terms of the problem set specifications, and continue to expand it as needed to support our core functions

**Focus:**
- Finalized the structure and types for the custom wire protocol
  - (If we tackle the custom protocol first, JSON can come as an an easier rephrasing of our byte packing into text-based fields)

**Packet Composition:**

- **Header:**
  - **Length (2 bytes):** Total size of the packet.
  - **Message Type (1 byte):** Determines the operation.
  - **Session Token (16 bytes):** For authentication.
- **Payload:**
  - Varies depending on our desired operation (e.g., username lengths, hashed passwords, message content).

**Defined Message Types:**

- `0x01`: Create Account Request  
- `0x02`: Create Account Response  
- `0x03`: Login Request  
- `0x04`: Login Response  
- `0x05`: List Accounts Request  
- `0x06`: List Accounts Response  
- `0x07`: Send Message Request  
- `0x08`: Send Message Response  
- `0x09`: Read Messages Request  
- `0x0A`: Read Messages Response  
- `0x0B`: Delete Message Request  
- `0x0C`: Delete Message Response  
- `0x0D`: Delete Account Request  
- `0x0E`: Delete Account Response  

**Packet Semantics:**
- By the problem set description, we feel motivated to store these fields as compactly as possible (while still giving a sense of platform scalability). Storing things like User ID as short ints (2 bytes) seems like a good way to save space, though this probably wouldn't be as good of an idea for messages, where we may have a massive amount on the platform at a given time (hence we'd want their UID field to be passed as 4 bytes or more)

**Notes:**
- Use Python's `struct.pack()` for packing/unpacking of bytes
- Protocol will be extendable as new operations arise, e.g. if we find we need new API calls for the GUI

---

## 02/08/2025 — Protocol Measurements / Performance Considerations
**Thought Process:**
- As was written up at the start of the file, today we conducted a performance test using a simulated server-side response for our client packets
- We've also been both (A) working on a GUI for the chat application using tkinter, and (B) working on the implementation of the custom wire protocol
  - Today we've set up the base case for client-server communication using a wire protocol that supports multiple sessions, and from here hope to code in base cases of our aforementioned immediate mode API that we want to model the connection as

**Focus:**
- Measure comparative packet sizes for custom wire protocol vs JSON

**Measurements:**

- **Custom Wire Protocol:**
  - `search_username`: 12 bytes
  - `create_account`: 44 bytes
  - `log_into_account`: 44 bytes
  - `log_out_of_account`: 39 bytes
  - `list_accounts`: 42 bytes
  - `display_conversation`: 41 bytes
  - `send_message`: 48 bytes
  - `read_messages`: 43 bytes
  - `delete_message`: 43 bytes
  - `delete_account`: 39 bytes

- **JSON Protocol:**
  - `search_username`: 54 bytes
  - `create_account`: 140 bytes
  - `log_into_account`: 142 bytes
  - `log_out_of_account`: 135 bytes
  - `list_accounts`: 147 bytes
  - `display_conversation`: 157 bytes
  - `send_message`: 168 bytes
  - `read_messages`: 149 bytes
  - `delete_message`: 152 bytes
  - `delete_account`: 131 bytes

**Performance Discussion:**
- As was discussed in lecture, modern networks tend to have extremely high bandwidth, with latency being the only point that we're unable to make faster (e.g. the speed of light / electricity). In this, our packet sizes (all of which are below 1KB), combined with the scale of our chat application in-practice (using across a few machines at most) lack a tangible effect on our application with respect to its real-time latency
  - This said, as these measurements for the custom protocol take 3-5x less data than their JSON protocol equivalents, we would be able to handle significantly more sessions before we'd start to put stress on our bandwidth. From this, it's clear that the custom protocol would offer a lot more support for things like concurrent sessions, server-side vertical scaling, etc. It's also **significantly** cleaner from an engineering standpoint: every byte has an express purpose.

---

## 02/09/2025 — Testing & Integration of Core Functionalities

**Thought Process:**
- At this point, we have (A) a base-level GUI, (B) a multi-session supporting client-server wire protocol, and (C) a specification for a custom wire protocol that makes sense. Now it seems time to use these nuts and bolts to create the core functionality of our chat app: GUI-based multi machine communication
- Our first priority from here is to code out the custom protocol, and alongside it use unit tests
  - A retrospect entry: I actually felt like the unit tests helped me to go **faster** when building out the wire protocol features. As long as I felt confident about how a feature worked and it passed the given unit tests, it made sense to move on, and to move attention onto cross-feature tests once features were completed (e.g. testing account creation, search, and deletion by creating an account, ensuring we can find it in searches, deleting it, and then ensuring that we can no longer find it in searches)
- By the end of today, I hope to get the core custom protocol functionalities working so that we can focus on GUI integration and JSON translation

**Focus:**
- Begin integration testing for core operations.
- Simulate client-server interactions using the custom protocol.

**Testing Highlights:**

- **Account Operations:**
  - Simulated client requests for account creation and login.
  - Verified correct session token generation and proper authentication flow.

- **Message Operations:**
  - Tested sending messages between users.
  - Ensured that messages are correctly stored in `GlobalConversations` and `GlobalMessageBase`.
  - Confirmed unread message handling by adding UIDs to the receiver’s queue.

- **Deletion Operations:**
  - Conducted tests on individual message deletion.
  - Verified that conversation deletion correctly iterates and removes all related messages.

**Outcome:**

- Core functionalities are operating as expected.
- Edge case handling and error conditions remain a focus for upcoming tests.

---

## 02/10/2025 — Server Endpoint / Client Integration Testing

**Testing Activities:**

- **Server Endpoint Verification:**
  - Checked endpoints for create account, login, list accounts, send/read messages, and deletion operations.
  - Monitored packet exchanges to ensure adherence to the protocol.

- **Client Integration:**
  - Developed a minimal client simulation to interact with server endpoints.
  - Tested session token propagation across operations.

- **Identified Issues:**
  - Minor packet parsing issues under heavy load.
  - Plans to enhance logging and error handling in the next phase.

---

## 02/11/2025 — GUI Integration / User Interaction

**Thought Process:**
- Now that the GUI and wire protocol both work independently, the top priority is to have an integration between them that allows for messaging between machines
  - We've successfully implemented this, giving us the core functionality of the chat application! From here, we plan to primarily work on JSON translation, unit testing, documentation, and debugging

**Focus:**
- Integrate backend operations with the front-end GUI prototype

**GUI Features Developed:**

- **Account Management:**
  - Users can create accounts or log in.
  - When a non-existent username is entered, the GUI prompts to create a new account.
  
- **Messaging Interface:**
  - Users can view conversation threads with individual contacts.
  - Real-time updates for new messages.
  - An “Unread Messages” section highlights unread messages and marks them as read once viewed.

- **Message Deletion:**
  - Implemented message selection (sent/received) with a click/un-click mechanism.
  - Confirmation dialogs ensure that users do not delete messages accidentally.

- **Account Deletion:**
  - Provides a clear “Are you sure?” prompt.
  - Warns users about cascading deletions (account and associated messages).

**UX Improvements:**

- Clear, immediate feedback for every user action.
- Dynamic GUI updates reflecting session state and conversation changes.
- Error messaging to help guide the user through issues (e.g., invalid credentials).

---

## 02/12/2025 — JSON Integrations, Debugging, and Consistency of Documentation

**Thought Process:**
- A high priority today was implementing JSON analogues for our custom wire protocol functions
  - Luckily, this largely consisted of Python dict-based operations, where we could have conditional branches of our existing client / server logic based on the types of packets that we wanted to transmit and decode
- GUI-side debugging went well, and we're able to perform all of the needed functionality within the problem set specification. From here, improvements to the code will likely be mainly stylistic / documentation, though we'll write further entries if we identify and build out nontrivial improvements to the existing system
- Clean up docstring formatting among functions, especially within GUI and server-side driver functions
- (Write an overview of core entities and structures into the README - Done!)

**Focus:**
- Final integration tests and debugging
- Consolidation of all components into a stable beta-ready system

**Integration Testing:**

- Conducted full end-to-end tests covering:
  - Account creation and login.
  - Sending, reading, and deleting messages.
  - Complete account deletion and its impact on conversations.
- Verified session token management:
  - Tokens refresh properly.
  - Expired tokens trigger a secure, automatic renewal process.

**Debugging Efforts:**

- Resolved packet parsing issues identified during heavy-load simulations.
- Improved error logging across server endpoints and the GUI.
- Ensured robust error handling for network interruptions.

**Documentation & Next Steps:**

- Updated protocol and design documentation to reflect final changes.
- Future optimizations:
  - Further refining DLL + hashmap structures for rapid deletion and list management.
  - Continued security reviews and performance optimizations.
- **Conclusion:**  
  - The system is stable and ready for demo day!
  - Plans for user testing and further enhancements based on feedback.

---


