import re
from typing import Optional, List, TypeVar, Generic

T = TypeVar('T')  # Generic type for values stored in the tree

class TSTNode(Generic[T]):
    def __init__(self, char: str):
        self.char = char          # The character stored in this node
        self.left = None          # Pointer to nodes with characters less than self.char
        self.eq = None            # Pointer to nodes with the next character in a string
        self.right = None         # Pointer to nodes with characters greater than self.char
        self.is_end = False       # Flag indicating if this node terminates a stored word
        self.value: Optional[T] = None  # Value (e.g., User instance) stored at terminal nodes

class TernarySearchTree(Generic[T]):
    def __init__(self):
        self.root = None

    def add(self, word: str, value: T) -> None:
        """
        Add a word to the TST with an associated value.
        In our case, word is username and value is User instance.
        """
        if not word:
            return
        self.root = self._add(self.root, word, value, 0)

    def _add(self, node: Optional[TSTNode[T]], word: str, value: T, index: int) -> TSTNode[T]:
        char = word[index]
        if node is None:
            node = TSTNode(char)
        
        if char < node.char:
            node.left = self._add(node.left, word, value, index)
        elif char > node.char:
            node.right = self._add(node.right, word, value, index)
        else:
            if index + 1 == len(word):
                node.is_end = True
                node.value = value  # Store the value at the terminal node
            else:
                node.eq = self._add(node.eq, word, value, index + 1)
        return node

    def get(self, word: str) -> Optional[T]:
        """Retrieve the value associated with a word."""
        if not word:
            return None
        
        node = self.root
        index = 0
        
        while node is not None:
            char = word[index]
            if char < node.char:
                node = node.left
            elif char > node.char:
                node = node.right
            else:
                index += 1
                if index == len(word):
                    return node.value if node.is_end else None
                node = node.eq
        
        return None

    def delete(self, word: str) -> None:
        """Delete a word and its associated value from the TST."""
        if not word:
            return
        self.root = self._delete(self.root, word, 0)

    def _delete(self, node: Optional[TSTNode[T]], word: str, index: int) -> Optional[TSTNode[T]]:
        if node is None:
            return None

        char = word[index]
        if char < node.char:
            node.left = self._delete(node.left, word, index)
        elif char > node.char:
            node.right = self._delete(node.right, word, index)
        else:
            if index + 1 == len(word):
                # Clear the value and unmark end-of-word
                node.is_end = False
                node.value = None
            else:
                node.eq = self._delete(node.eq, word, index + 1)

        # Cleanup: if this node is no longer needed, remove it
        if not node.is_end and node.eq is None:
            if node.left is None and node.right is None:
                return None
        return node

    def regex_search(self, pattern: str) -> List[T]:
        """
        Search for and return all values whose keys match the given wildcard pattern.
        Wildcard rules:
          - '?' matches any single character
          - '*' matches any sequence of characters (including empty)
        Returns list of values (User instances in our case) instead of just words.
        """
        regex_pattern = '^' + re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.') + '$'
        prog = re.compile(regex_pattern)
        
        results = []  # Will store tuples of (word, value)
        self._collect(self.root, "", results)
        
        # Filter based on pattern and return only the values
        return [value for word, value in results if prog.match(word)]

    def _collect(self, node: Optional[TSTNode[T]], prefix: str, result: List[tuple[str, T]]) -> None:
        """
        Recursively traverse the TST and collect all (word, value) pairs.
        Modified to collect values along with words.
        """
        if node is None:
            return

        # Traverse left subtree
        self._collect(node.left, prefix, result)

        # Process current node
        new_prefix = prefix + node.char
        if node.is_end and node.value is not None:
            result.append((new_prefix, node.value))

        # Traverse equal subtree
        self._collect(node.eq, new_prefix, result)

        # Traverse right subtree
        self._collect(node.right, prefix, result)
