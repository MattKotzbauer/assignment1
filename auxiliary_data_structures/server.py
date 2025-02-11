# server.py
import socket
import selectors
import types
import sys

if len(sys.argv) != 3:
    print("Usage: python server.py PORT HOST")
    sys.exit(1)

try:
    PORT = int(sys.argv[1])
    HOST = sys.argv[2]
except ValueError:
    print("PORT must be an integer")
    sys.exit(1)

sel = selectors.DefaultSelector()

def handle_packet(packet_content: str) -> None:
    """Process received packet content from client"""
    print(f"Server received: {packet_content}")
    # Add your server-side packet processing logic here
    return packet_content.upper()  # Example: convert to uppercase

def send_packet(packet_content: str, sock) -> None:
    """Send packet to client"""
    encoded_content = packet_content.encode('utf-8')
    sock.send(encoded_content)

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            decoded_data = recv_data.decode('utf-8')
            response = handle_packet(decoded_data)
            data.outb += response.encode('utf-8')
        else:
            print("Closing connection")
            sel.unregister(sock)
            sock.close()
            
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]

def main():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((HOST, PORT))
    lsock.listen()
    print(f"Listening on {(HOST, PORT)}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    
    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == "__main__":
    main()
