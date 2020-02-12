"""
context.py
~~~~~~~~~~
Access main module from tests folder
"""
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../qualysapi")))

print("USING context.py")
try:
    import qualysapi
except ImportError as E:
    print(E)


if __name__ == "__main__":
    print(os.path.abspath(os.path.join(os.path.dirname(__file__), "../qualysapi")))
    print(__doc__)
    print("\tMODULES")
    print(qualysapi.__doc__)
