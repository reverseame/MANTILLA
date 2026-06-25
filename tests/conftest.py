import os
import sys

# Make the modules under src/ importable as top-level modules in tests.
SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)
