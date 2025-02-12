import socket
from typing import Optional
import time
from socket_handler import Client

def test_search_username():
    client = Client(host = "127.0.0.1", port = 65432, use_json = True)
    client.connect()
    
    try:
        # Test searching for 'alice'
        alice_available = client.search_username("alice")
        print(f"Test 1 - Username 'alice' available? {alice_available}")
        
        client.disconnect()
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        client.disconnect()
        return False

if __name__ == "__main__":
    test_result = test_search_username()
    print(f"\nAll tests {'passed' if test_result else 'failed'}")
