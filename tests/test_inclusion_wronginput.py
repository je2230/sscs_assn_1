import sys
import json
from jsonschema import validate
import subprocess

def test_inclusion_wronginput():
    logIndex = 692782562
    result = subprocess.run(
        ['python', 'main.py', '--inclusion', str(logIndex)],
        capture_output=True,
        text=True
    )
    output = result.stdout
    # data = json.loads(output)

    print(output)
