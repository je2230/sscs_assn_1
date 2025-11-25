"""Software Supply Chain Security HW 2 - Rekor monitor

Jess Ermi - je2230
"""

import argparse
import base64
import json
import requests as r
from cryptography.exceptions import InvalidSignature
from .util import extract_public_key, verify_artifact_signature
from .merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    RootMismatchError,
)


CONST_URL = "https://rekor.sigstore.dev/api/v1/log/"


def get_log_entry(log_index, debug=False):
    """fetches log entry from api given specific log index

    Args:
        log_index (int): index of log entry in question
        debug (bool, optional): if true, prints verbose output to terminal. Defaults to False.

    Returns:
        tuple: returns (signature, certificate) if no errors, false if errors
    """

    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index <= 0:
        if debug:
            print("In get_log_entry: index invalid")
        return False

    api_url = f"{CONST_URL}entries?logIndex={str(log_index)}"
    res = r.get(api_url, timeout=10)

    if res.status_code == 200:
        log_entry = res.json()
        key = list(log_entry.keys())[0]

        body = json.loads(base64.b64decode(log_entry[key]["body"].encode()).decode())
        sign = body["spec"]["signature"]["content"]

        b64_cert = body["spec"]["signature"]["publicKey"]["content"]
        cert = base64.b64decode(b64_cert.encode()).decode()

        if debug:
            print("In get_log_entry:\n", "Signature: ", sign, "\nCert: ", cert)

        return (sign, cert)

    if debug:
        print("In get_log_entry: api call failed with code", res.status_code)
    return False


def get_verification_proof(log_index, debug=False):
    """fetches verification proof from api for specific log entry given index

    Args:
        log_index (int): index of log entry in question
        debug (bool, optional): if true, prints verbose output to terminal. Defaults to False.

    Returns:
        dict: returns verification proof as a dict if no errors, false if errors
    """

    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index <= 0:
        if debug:
            print("In get_verification_proof: index invalid")
        return False

    # get verification proof from api
    api_url = f"{CONST_URL}entries?logIndex={str(log_index)}"
    res = r.get(api_url, timeout=10)

    if res.status_code == 200:
        log_entry = res.json()
        key = list(log_entry.keys())[0]

        ver = log_entry[key]["verification"]["inclusionProof"]

        # compute leaf hash
        log_entry_body = log_entry[key].get("body")
        leaf_hash = compute_leaf_hash(log_entry_body)
        ver["leafHash"] = leaf_hash

        if debug:
            print("In get_verification_proof:\nVer:", ver)

        return ver

    if debug:
        print(f"In get_verification_proof: api call failed with code {res.status_code}")
    return False


def inclusion(log_index, artifact_filepath, debug=False):
    """verifies an artifact's signature, if it is included in rekor log

    Args:
        log_index (int): index of log entry in question
        artifact_filepath (str): path of artifact file to verify signature/inclusion of
        debug (bool, optional): if true, prints verbose output to terminal. Defaults to False.

    Returns:
        bool: returns False if there are errors, else True
    """

    # verify that log index and artifact filepath values are sane
    # (log index verification happens in both helper functions)
    try:
        with open(artifact_filepath, "rb") as art_file:
            art_file.read()

    except OSError as error:
        if debug:
            print(
                f"In inclusion: failed to read from {artifact_filepath} with exception {error}"
            )

        return False

    sign, cert = get_log_entry(log_index, debug)
    sign = base64.b64decode(sign.encode())

    # extract_public_key(certificate)
    pub_key = extract_public_key(cert.encode())

    # verify_artifact_signature(signature, public_key, artifact_filepath)
    try:
        verify_artifact_signature(sign, pub_key, artifact_filepath)
        print("Signature is valid")

    except InvalidSignature as error:
        if debug:
            print(f"In inclusion: error verifying signature - {error}")

    # get_verification_proof(log_index)
    ver_map = get_verification_proof(log_index, debug)

    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    try:
        verify_inclusion(
            DefaultHasher,
            ver_map["logIndex"],
            ver_map["treeSize"],
            ver_map["leafHash"],
            ver_map["hashes"],
            ver_map["rootHash"],
            debug,
        )
        print("Offline root hash calculation for inclusion verified.")

        return True

    except ValueError as error:
        print(f"In inclusion: Failed to verify inclusion with exception {error}")
        return False

    except RootMismatchError as error:
        print(f"In inclusion: Failed to verify inclusion with exception {error}")
        return False


def get_latest_checkpoint(debug=False):
    """fetches latest checkpoint from rekor api

    Args:
        debug (bool, optional): if true, prints verbose output to terminal. Defaults to False.

    Returns:
        dict: returns checkpoint as json dictionary object if no errors, else returns false
    """

    res = r.get(CONST_URL, timeout=10)

    if res.status_code == 200:
        return res.json()

    if debug:
        print(f"In get_latest_checkpoint: API call failed with code {res.status_code}")
    return False


def consistency(prev_checkpoint, debug=False):
    """verifies an old rekor checkpoint is consistent with the newest checkpoint

    Args:
        prev_checkpoint (dict): dictionary holding tree id, tree size, root hash
        debug (bool, optional): if true, prints verbose output to terminal. Defaults to False.

    Returns:
        bool: returns False if there are errors, else True
    """

    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        if debug:
            print("prev_checkpoint is empty. Please enter values")
        return False

    tree_size = str(prev_checkpoint["treeSize"])
    tree_id = str(prev_checkpoint["treeID"])

    # get_latest_checkpoint()
    new_proof = get_latest_checkpoint()

    if new_proof:
        try:
            new_size = new_proof["treeSize"]

            url = f"{CONST_URL}proof?firstSize={tree_size}&lastSize={new_size}&treeID={tree_id}"
            res = r.get(url, timeout=10)

            if res.status_code == 200:
                old_proof = res.json()

                verify_consistency(
                    DefaultHasher,
                    prev_checkpoint["treeSize"],
                    new_proof["treeSize"],
                    old_proof["hashes"],
                    prev_checkpoint["rootHash"],
                    new_proof["rootHash"],
                )
                print("Consistency verification successful.")
                return True

            return False

        except ValueError as error:
            print(f"In inclusion: Failed to verify inclusion with exception {error}")
            return False

        except RootMismatchError as error:
            print(f"In inclusion: Failed to verify inclusion with exception {error}")
            return False

    return False


def main():
    """main functiuon: parses command line arguments, calls correct functions

    Returns:
        none: program exits after execution
    """

    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
