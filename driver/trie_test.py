from tst_implementation import TernarySearchTree
from core_entities import User

def create_test_user(user_id: int, username: str) -> User:
    """Helper function to create test users"""
    password_hash = f"dummy_hash_{username}"  # Just for testing
    return User(user_id, username, password_hash)

def test_tst_with_users():
    # Initialize TST with User as value type
    tst = TernarySearchTree[User]()
    
    # Create some test users
    test_users = [
        create_test_user(1, "alice"),
        create_test_user(2, "allen"),
        create_test_user(3, "bob"),
        create_test_user(4, "bobby"),
        create_test_user(5, "carol"),
        create_test_user(6, "carly"),
        create_test_user(7, "dave")
    ]
    
    # Add users to TST
    print("Adding users to TST...")
    for user in test_users:
        tst.add(user.username, user)
    
    # Test 1: Get specific user
    print("\nTest 1: Direct user lookup")
    alice = tst.get("alice")
    print(f"Looking up 'alice': Found user with ID {alice.userID if alice else 'not found'}")
    
    # Test 2: Pattern matching
    print("\nTest 2: Pattern matching 'a?l*'")
    matching_users = tst.regex_search("a?l*", return_values=True)
    print("Matching users:", [f"{user.username} (ID: {user.userID})" for user in matching_users])
    
    # Test 3: Get all users
    print("\nTest 3: Getting all users")
    all_users = tst.regex_search("*", return_values=True)
    print("All users:", [f"{user.username} (ID: {user.userID})" for user in all_users])
    
    # Test 4: Delete user and verify
    print("\nTest 4: Deleting 'allen' and verifying")
    tst.delete("allen")
    remaining_users = tst.regex_search("*", return_values=True)
    print("Remaining users:", [f"{user.username} (ID: {user.userID})" for user in remaining_users])
    
    # Test 5: Try to get deleted user
    print("\nTest 5: Attempting to get deleted user 'allen'")
    deleted_user = tst.get("allen")
    print(f"Result of getting 'allen': {deleted_user if deleted_user else 'Not found (as expected)'}")

if __name__ == "__main__":
    test_tst_with_users()



    
