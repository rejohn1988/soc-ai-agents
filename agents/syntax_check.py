"""
Syntax checker for agent files
"""

import ast
import sys
from pathlib import Path

def check_syntax(filename):
    """Check Python syntax of a file"""
    try:
        with open(filename, 'r') as f:
            ast.parse(f.read())
        print(f"✓ {filename} - Syntax OK")
        return True
    except SyntaxError as e:
        print(f"✗ {filename} - Syntax Error: {e}")
        return False

if __name__ == "__main__":
    # Check all Python files in agents directory
    agents_dir = Path(__file__).parent
    errors = 0
    
    for py_file in agents_dir.glob("*.py"):
        if py_file.name != "syntax_check.py":
            if not check_syntax(py_file):
                errors += 1
    
    sys.exit(errors)
