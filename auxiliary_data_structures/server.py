import socket
import sys
import threading

class Server:
    def __init__(self, port: int, host: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.clients = []
        
    def start(self):
        print(f"Server started on {self.sock.getsockname()}")
        while True:
            client_socket, address = self.sock.accept()
            self.clients.append(client_socket)
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            
    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                self.handle_packet(data)
            except:
                break
        client_socket.close()
        self.clients.remove(client_socket)
        
    def send_packet(self, packet_content: str):
        for client in self.clients:
            try:
                client.send(packet_content.encode())
            except:
                continue

    def handle_packet(self, packet_content: str):
        print(f"Received: {packet_content}")
        # Add your packet handling logic here
        # self.send_packet("foo")

            
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python server.py PORT HOST")
        sys.exit(1)
        
    port = int(sys.argv[1])
    host = sys.argv[2]
    
    server = Server(port, host)
    server.start()
