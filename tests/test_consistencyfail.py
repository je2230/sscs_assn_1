import sys
import json
from jsonschema import validate
import subprocess

def test_consistency_fail():
    tree_id = 1
    tree_size = 1
    root_hash = 'abc'
    result = subprocess.run(
        ['python', 'main.py', '--consistency', '--tree-id', str(tree_id), '--tree-size', str(tree_size), '--root-hash', str(root_hash)],
        capture_output=True,
        text=True
    )
    output = result.stdout


