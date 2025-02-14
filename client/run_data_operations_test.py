#!/usr/bin/env python3
import json
from socket_handler import Client

class TestClient(Client):
    """
    A subclass of Client that overrides send_request to record the
    length of data that would be sent and returns a dummy response.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # List to store the lengths of the packets sent.
        self.sent_data_lengths = []

    def send_request(self, request_content: bytes) -> bytes:
        # Record the length of this outgoing packet.
        self.sent_data_lengths.append(len(request_content))
        
        # If using JSON protocol, the request is a JSON object after a 4-byte length header.
        if self.use_json:
            req = json.loads(request_content[4:].decode('utf-8'))
            opcode = req.get("opcode")
            # Provide dummy JSON responses for opcodes 0x01 to 0x19:
            if opcode == "search_username":
                resp = {"opcode": "search_username_response", "available": True}
            elif opcode == "create_account":
                resp = {"opcode": "create_account_response", "session_token": "a" * 64}
            elif opcode == "log_into_account":
                resp = {"opcode": "log_into_account_response", "success": True,
                        "session_token": "a" * 64, "unread_count": 0}
            elif opcode == "log_out_of_account":
                resp = {"opcode": "log_out_of_account_response"}
            elif opcode == "list_accounts":
                resp = {"opcode": "list_accounts_response", "accounts": ["bob", "charlie"]}
            elif opcode == "display_conversation":
                resp = {"opcode": "display_conversation_response", "messages": []}
            elif opcode == "send_message":
                resp = {"opcode": "send_message_response"}
            elif opcode == "read_messages":
                resp = {"opcode": "read_messages_response"}
            elif opcode == "delete_message":
                resp = {"opcode": "delete_message_response"}
            elif opcode == "delete_account":
                resp = {"opcode": "delete_account_response"}
            else:
                resp = {"opcode": opcode + "_response"}
            resp_bytes = json.dumps(resp).encode('utf-8')
            # Prepend a 4-byte header with the length of the JSON body.
            return len(resp_bytes).to_bytes(4, byteorder='big') + resp_bytes
        
        else:
            # Binary mode: the opcode is at byte 4.
            opcode = request_content[4]
            if opcode == 0x01:
                # search_username: response: [4-byte length][0x02][status (0x00 means available)]
                body = bytes([0x02, 0x00])
            elif opcode == 0x03:
                # create_account: response: [4-byte length][0x04][32-byte token]
                body = bytes([0x04]) + (b'a' * 32)
            elif opcode == 0x05:
                # log_into_account: response: [4-byte length][0x06][status][32-byte token][4-byte unread count]
                body = bytes([0x06, 0x00]) + (b'a' * 32) + (0).to_bytes(4, byteorder='big')
            elif opcode == 0x07:
                # log out of account: response: [4-byte length][0x08]
                body = bytes([0x08])
            elif opcode == 0x09:
                # list_accounts: response: [4-byte length][0x10][2-byte account count] + account entries.
                accounts = [b"bob", b"charlie"]
                body = bytes([0x10]) + len(accounts).to_bytes(2, byteorder='big')
                for account in accounts:
                    body += len(account).to_bytes(2, byteorder='big') + account
            elif opcode == 0x11:
                # display_conversation: response: [4-byte length][0x12][4-byte message count]
                body = bytes([0x12]) + (0).to_bytes(4, byteorder='big')
            elif opcode == 0x13:
                # send_message: response: [4-byte length][0x14]
                body = bytes([0x14])
            elif opcode == 0x15:
                # read_messages: response: [4-byte length][0x16]
                body = bytes([0x16])
            elif opcode == 0x17:
                # delete_message: response: [4-byte length][0x18]
                body = bytes([0x18])
            elif opcode == 0x19:
                # delete_account: response: [4-byte length][0x20]
                body = bytes([0x20])
            else:
                # Default dummy response.
                body = bytes([opcode + 1])
            return len(body).to_bytes(4, byteorder='big') + body

def run_measurements():
    # Define only the operations with opcodes 0x01 to 0x19.
    # Note: The mapping between operations and opcodes is as follows:
    #   search_username: 0x01, create_account: 0x03, log_into_account: 0x05,
    #   log_out_of_account: 0x07, list_accounts: 0x09,
    #   display_conversation: 0x11, send_message: 0x13,
    #   read_messages: 0x15, delete_message: 0x17, delete_account: 0x19.
    operations = [
        ("search_username", {"username": "alice"}),
        ("create_account", {"username": "alice", "password": "secret"}),
        ("log_into_account", {"username": "alice", "password": "secret"}),
        ("log_out_of_account", {"user_id": 1, "session_token": "a" * 64}),
        ("list_accounts", {"user_id": 1, "session_token": "a" * 64, "wildcard": "a"}),
        ("display_conversation", {"user_id": 1, "session_token": "a" * 64, "conversant_id": 2}),
        ("send_message", {"user_id": 1, "session_token": "a" * 64, "recipient_id": 2, "message": "Hello"}),
        ("read_messages", {"user_id": 1, "session_token": "a" * 64, "num_messages": 5}),
        ("delete_message", {"user_id": 1, "message_uid": 1234, "session_token": "a" * 64}),
        ("delete_account", {"user_id": 1, "session_token": "a" * 64}),
    ]

    print("=== Measurements for Custom Binary Protocol ===")
    binary_client = TestClient("localhost", 0, use_json=False)
    for op, params in operations:
        binary_client.sent_data_lengths = []
        try:
            if op == "search_username":
                binary_client.search_username(params["username"])
            elif op == "create_account":
                binary_client.create_account(params["username"], params["password"])
            elif op == "log_into_account":
                binary_client.log_into_account(params["username"], params["password"])
            elif op == "log_out_of_account":
                binary_client.log_out_of_account(params["user_id"], params["session_token"])
            elif op == "list_accounts":
                binary_client.list_accounts(params["user_id"], params["session_token"], params["wildcard"])
            elif op == "display_conversation":
                binary_client.display_conversation(params["user_id"], params["session_token"], params["conversant_id"])
            elif op == "send_message":
                binary_client.send_message(params["user_id"], params["session_token"], params["recipient_id"], params["message"])
            elif op == "read_messages":
                binary_client.read_messages(params["user_id"], params["session_token"], params["num_messages"])
            elif op == "delete_message":
                binary_client.delete_message(params["user_id"], params["message_uid"], params["session_token"])
            elif op == "delete_account":
                binary_client.delete_account(params["user_id"], params["session_token"])
            print(f"Binary op '{op}' sent {binary_client.sent_data_lengths[-1]} bytes")
        except Exception as e:
            print(f"Binary op '{op}' encountered an error: {e}")

    print("\n=== Measurements for JSON Protocol ===")
    json_client = TestClient("localhost", 0, use_json=True)
    for op, params in operations:
        json_client.sent_data_lengths = []
        try:
            if op == "search_username":
                json_client.search_username(params["username"])
            elif op == "create_account":
                json_client.create_account(params["username"], params["password"])
            elif op == "log_into_account":
                json_client.log_into_account(params["username"], params["password"])
            elif op == "log_out_of_account":
                json_client.log_out_of_account(params["user_id"], params["session_token"])
            elif op == "list_accounts":
                json_client.list_accounts(params["user_id"], params["session_token"], params["wildcard"])
            elif op == "display_conversation":
                json_client.display_conversation(params["user_id"], params["session_token"], params["conversant_id"])
            elif op == "send_message":
                json_client.send_message(params["user_id"], params["session_token"], params["recipient_id"], params["message"])
            elif op == "read_messages":
                json_client.read_messages(params["user_id"], params["session_token"], params["num_messages"])
            elif op == "delete_message":
                json_client.delete_message(params["user_id"], params["message_uid"], params["session_token"])
            elif op == "delete_account":
                json_client.delete_account(params["user_id"], params["session_token"])
            print(f"JSON op '{op}' sent {json_client.sent_data_lengths[-1]} bytes")
        except Exception as e:
            print(f"JSON op '{op}' encountered an error: {e}")

if __name__ == "__main__":
    run_measurements()
