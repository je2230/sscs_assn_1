import sys
import json
from jsonschema import validate
import subprocess

import main


def test_inclusion_wronginput2():
    logIndex = -1
    result = subprocess.run(
        ['python', 'main.py', '--inclusion', str(logIndex), '--artifact', 'artifact.md'],
        capture_output=True,
        text=True
    )
    output = result.stdout
    # data = json.loads(output)

    print(output)
