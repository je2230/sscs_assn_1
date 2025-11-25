import sys
import json
from jsonschema import validate
import subprocess

def test_consistency_wronginput2():
    tree_id = -1
    tree_size = -1
    root_hash = 'a4ace1939258b717cb5a17d5fcc80ac23878e0acabad6bf06ca2428454a1d2af'
    result = subprocess.run(
        ['python', 'main.py', '--consistency', '--tree-id', str(tree_id), '--tree-size', str(tree_size), '--root-hash', str(root_hash)],
        capture_output=True,
        text=True
    )
    output = result.stdout
    print(output)

