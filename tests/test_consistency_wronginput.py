import sys
import json
from jsonschema import validate
import subprocess

def test_consistency_wronginput():
    tree_id = 1193050959916656506
    tree_size = 570880561
    root_hash = 'a4ace1939258b717cb5a17d5fcc80ac23878e0acabad6bf06ca2428454a1d2af'
    result = subprocess.run(
        ['python', 'main.py', '--consistency'],
        capture_output=True,
        text=True
    )
    output = result.stdout


