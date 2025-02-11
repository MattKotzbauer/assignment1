# client.py
import socket
import selectors
import types
import sys

sel = selectors.DefaultSelector()

def handle_packet(packet_content: str) -> None:
    """Process received packet from server"""
    print(f"Client received: {packet_content}")
    # Add your client-side packet processing logic here

def send_packet(packet_content: str, sock) -> None:
    """Send packet to server"""
    encoded_content = packet_content.encode('utf-8')
    sock.send(encoded_content)

def start_connection(host, port):
    addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex(addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    data = types.SimpleNamespace(
        addr=addr,
        inb=b"",
        outb=b"",
        connected=False
    )
    sel.register(sock, events, data=data)
    return sock

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            handle_packet(recv_data.decode('utf-8'))
        else:
            print("Closing connection")
            sel.unregister(sock)
            sock.close()
            sys.exit()

    if mask & selectors.EVENT_WRITE:
        if not data.connected:
            data.connected = True

def main():
    if len(sys.argv) != 3:
        print("Usage: python client.py PORT HOST")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        host = sys.argv[2]
    except ValueError:
        print("PORT must be an integer")
        sys.exit(1)
        
    
    sock = start_connection(host, port)
    
    try:
        while True:
            events = sel.select(timeout=1)
            for key, mask in events:
                service_connection(key, mask)
            
            # Example: Allow user input for sending messages
            message = input("Enter message (or 'quit' to exit): ")
            if message.lower() == 'quit':
                break
            send_packet(message, sock)
            
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
        sock.close()

if __name__ == "__main__":
    main()
