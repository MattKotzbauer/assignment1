

Design Notebook:


Thinking about the shape of our packet is something I want to do carefully since I've never written a wire protocol from the ground-up before. Thinking on first principles, I would think our protocol should adhere to the following axioms:
- Specifying length in the beginning to simplify the handling of multiple packets
- Specifying message type as well in the beginning, and having the remaining content of the message and its interpretation be based on that
- Given this, I think that we should define request and response types for each of the following:
  - Creating account
  - Login
  - Listing accounts
  - Sending a message
  - Reading a message
  - Deleting a message
  - Deleting accounts
- Any transaction would then likely start with a handshake between the client and server, resulting in a client storing a session token signifying a shared session with the server (with some resetting interval, perhaps 30 minutes?)
- I think SQL might be a bit heavyweight as a means of storage: the primary access pattern that we need is, when specifying a sender and receiver for a string of messages, being able to retrieve said string of messages in chronological order



02/05/2025: 

02/04/2025:


02/03/2025:
- Since I used primarily SQL last summer, I feel relatively comfortable with how the data might be stored: I'd probably use something like sqlite to store all of the messages in a central database (as the scalability / ordering of our data doesn't seem to be a concern)
- The first question I'm considering is, in turn, the way that we want to store our messages
  - For operations like searches, deletions, and updates, we'd probably want a way to unambiguously refer to the message. I would favor global message UID's for this
    - If a client wants to delete a message, we would need this to also be accessible client-side?
  - Other things that come to mind that we'd want to store and potentially use:
    - Message Sender ID, Message Receiver ID (for displaying messages from a single chat)
    - Message Content
    - Message Timestamp
      - (Most chat apps support timestamp - we could also use the UID to sort messages chronologically, but it seems intuitive that users should be able to see when messages were sent)
- I've never implemented a wire protocol before, but here are my initial ideas:
  - Specifying the length of the message the start in some type of universal length (2 bytes should suffice?) would be fast for processing the messasge
  - We'd probably also want a byte or so specifying the type of message (send message, delete message, update message, etc)
  - The content of the packet would then probably depend on the type of message  
  - Python's struct.pack() seems useful for contiguous byte storage
- Miscellaneous thoughts:
  - Perhaps large-scale for sending, we'd want the following:
    1. Client sends a message to server with small package content (e.g. 'send', 'length', 'content')
    2. Server assembles full metadata thing (e.g. UID, timestamp, client / sender ID)
    3. Server sends all such things back to client to display
       * (perhaps both (A) at start of session and (B) whenever there's an update in state concerning the (client, sender ID pair), the server updates the messages that it shows to both clients)
       	 * (or perhaps there's an event listener on the side of the GUI that re-queries the database when this occurs? Or perhaps we only need to append the most recent message)
