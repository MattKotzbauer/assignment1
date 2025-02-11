import socket
import sys
import threading

class Client:
    def __init__(self, port: int, host: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        
    def start(self):
        print(f"Connected to server at {self.sock.getpeername()}")
        receive_thread = threading.Thread(target=self.receive_packets)
        receive_thread.start()
        
        while True:
            try:
                message = input()
                self.send_packet(message)
            except KeyboardInterrupt:
                break
        
        self.sock.close()
        
    def receive_packets(self):
        while True:
            try:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                self.handle_packet(data)
            except:
                break
        self.sock.close()
        
    def handle_packet(self, packet_content: str):
        print(f"Received: {packet_content}")
        # Add your packet handling logic here
        
    def send_packet(self, packet_content: str):
        try:
            self.sock.send(packet_content.encode())
        except:
            print("Failed to send packet")
            self.sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py PORT HOST")
        sys.exit(1)
        
    port = int(sys.argv[1])
    host = sys.argv[2]
    
    client = Client(port, host)
    client.start()
