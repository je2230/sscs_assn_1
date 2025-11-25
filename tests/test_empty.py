import sys
import json
from jsonschema import validate
import subprocess

def test_empty():
    result = subprocess.run(
        ['python', 'main.py'],
        capture_output=True,
        text=True
    )
    output = result.stdout
    print(output)

