import sys
import json
from jsonschema import validate
import subprocess

checkpoint_schema = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"}
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"]
}

def test_checkpoint():
    result = subprocess.run(
        ['python', 'main.py', '-c'],
        capture_output=True,
        text=True
    )
    output = result.stdout
    try:
        data = json.loads(output)
        validate(instance=data, schema=checkpoint_schema)
    except Exception as e:
        print("failed with exception", e)

