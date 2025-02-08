import re
from typing import Optional, List, TypeVar, Generic

class TSTNode:
    def __init__(self, char):
        self.char = char          # The character stored in this node.
        self.left = None          # Pointer to nodes with characters less than self.char.
        self.eq = None            # Pointer to nodes with the next character in a string.
        self.right = None         # Pointer to nodes with characters greater than self.char.
        self.is_end = False       # Flag indicating if this node terminates a stored word.
        self.value = None
        
class TernarySearchTree:
    def __init__(self):
        self.root = None

    def add(self, word, value):
        """Add a word (account) to the TST."""
        if not word:
            return
        self.root = self._add(self.root, word, value, 0)

    def _add(self, node, word, index):
        char = word[index]
        if node is None:
            node = TSTNode(char)
        if char < node.char:
            node.left = self._add(node.left, word, index)
        elif char > node.char:
            node.right = self._add(node.right, word, index)
        else:
            if index + 1 == len(word):
                node.is_end = True
            else:
                node.eq = self._add(node.eq, word, index + 1)
        return node

    def delete(self, word):
        """Delete a word (account) from the TST so it is no longer found."""
        if not word:
            return
        self.root = self._delete(self.root, word, 0)

    def _delete(self, node, word, index):
        if node is None:
            return None

        char = word[index]
        if char < node.char:
            node.left = self._delete(node.left, word, index)
        elif char > node.char:
            node.right = self._delete(node.right, word, index)
        else:
            # If we have matched the current character...
            if index + 1 == len(word):
                # Unmark the end-of-word flag.
                node.is_end = False
            else:
                node.eq = self._delete(node.eq, word, index + 1)

        # Cleanup: if this node is no longer needed, remove it.
        if not node.is_end and node.eq is None:
            # If no children exist in left/right, this node is not required.
            if node.left is None and node.right is None:
                return None
        return node

    def regex_search(self, pattern):
        """
        Search for and return all words that match the given wildcard pattern.
        Wildcard rules:
          - '?' matches any single character.
          - '*' matches any sequence of characters (including the empty sequence).
        """
        # Convert the wildcard pattern to a proper regular expression:
        # First escape any regex-special characters, then unescape our wildcards.
        regex_pattern = '^' + re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.') + '$'
        prog = re.compile(regex_pattern)
        all_words = []
        self._collect(self.root, "", all_words)
        # Filter words that match the regex.
        return [word for word in all_words if prog.match(word)]

    def _collect(self, node, prefix, result):
        """
        Recursively traverse the TST and collect all words.
        The traversal uses the following idea:
         - For each node, traverse left (which does not add the current node's character)
         - Append the current node's character and, if this marks end-of-word, record the word.
         - Then traverse the equal branch (adding further characters)
         - Finally traverse right (with the same prefix as the current node)
        """
        if node is None:
            return

        # Traverse left subtree
        self._collect(node.left, prefix, result)

        # Process current node: add its character to the prefix.
        new_prefix = prefix + node.char
        if node.is_end:
            result.append(new_prefix)

        # Traverse the equal subtree (continuing the word)
        self._collect(node.eq, new_prefix, result)

        # Traverse right subtree (keeping the same prefix)
        self._collect(node.right, prefix, result)

# -----------------------
# Example Usage:
# -----------------------

if __name__ == "__main__":
    tst = TernarySearchTree()
    accounts = ["alice", "allen", "bob", "bobby", "carol", "carly", "dave"]
    for account in accounts:
        tst.add(account)

    print("All accounts:")
    print(tst.regex_search("*"))  # Using '*' to match all accounts

    print("\nAccounts matching pattern 'a?l*':")
    # For instance, pattern 'a?l*' might match "alice" and "allen" 
    matches = tst.regex_search("a?l*")
    print(matches)

    print("\nDeleting account 'allen' ...")
    tst.delete("allen")
    print("Accounts after deletion:")
    print(tst.regex_search("*"))
