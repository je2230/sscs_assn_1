import sys
import json
from jsonschema import validate
import subprocess

import main


def test_inclusion():
    logIndex = 508008011
    result = subprocess.run(
        ['python', 'main.py', '--inclusion', str(logIndex), '--artifact', 'artifact.md'],
        capture_output=True,
        text=True
    )
    output = result.stdout
    data = json.loads(output)

    validate(instance=data)
