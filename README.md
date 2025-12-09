[![CD Pipeline](https://github.com/je2230/sscs_assn_1/actions/workflows/cd.yml/badge.svg)](https://github.com/je2230/sscs_assn_1/actions/workflows/cd.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/je2230/sscs_assn_1/badge)] [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11592/badge)](https://www.bestpractices.dev/projects/11592)

# Python Rekor Monitor 

This project is a simple Rekor log monitor written in python. You can verify that an artifact has been signed and not modified since signing, get the latest checkpoint, and verify consistency between earlier logs and later logs. 

### Usage

Get latest checkpoint:
    python3 main.py -c

Verify inclusion of an artifact:
    python3 main.py --inclusion LOG_INDEX --artifact ARTIFACT_FILEPATH

Verify consistency of the most recent checkpoint and an earlier checkpoint:
    python3 main.py --consistency --tree-id TREE_ID --tree-size TREE_SIZE --root-hash ROOT_HASH

### Maintainers and Contributors
Just me for now! Jess Ermi - je2230 on github



