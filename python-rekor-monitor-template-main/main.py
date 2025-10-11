import argparse
import requests as r
import base64
import json
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

CONST_URL = "https://rekor.sigstore.dev/api/v1/log/"

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index <= 0:
        if debug:
            print("In get_log_entry: index invalid")
        return False

    api_url = f"{CONST_URL}entries?logIndex={str(log_index)}"
    res = r.get(api_url)

    if res.status_code == 200:
        log_entry = res.json()
        key = list(log_entry.keys())[0]

        body = json.loads(base64.b64decode(log_entry[key]["body"].encode()).decode())
        sign = body["spec"]["signature"]["content"]

        b64_cert = body["spec"]["signature"]["publicKey"]["content"]
        cert = base64.b64decode(b64_cert.encode()).decode()

        if debug:
            print ("In get_log_entry:\n", "Signature: ", sign, "\nCert: ", cert)
        
        return (sign, cert)

    else:
        if debug:
            print("In get_log_entry: api call failed with code", res.status_code)
        return False


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index <= 0:
        if debug:
            print("In get_verification_proof: index invalid")
        return False

    # get verification proof from api
    api_url = f"{CONST_URL}entries?logIndex={str(log_index)}"
    res = r.get(api_url)

    if res.status_code == 200:
        log_entry = res.json()
        key = list(log_entry.keys())[0]

        ver = log_entry[key]["verification"]["inclusionProof"]

        # compute leaf hash
        log_entry_body = log_entry[key].get('body') 
        leaf_hash = compute_leaf_hash(log_entry_body) 
        ver["leafHash"] = leaf_hash

        if debug:
            print("In get_verification_proof:\nVer:", ver)

        return ver
    
    else:
        if debug:
            print(f"In get_verification_proof: api call failed with code {res.status_code}")
        return False


def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane (log index verification happens in both helper functions)
    try:
        with open(artifact_filepath, "rb") as fd:
            fd.read()     
         
    except Exception as e:
        if debug:
            print(f"In inclusion: failed to read from artifact file {artifact_filepath} with exception {e}")

        return False
    
    sign, cert = get_log_entry(log_index)

    # extract_public_key(certificate)
    pub_key = extract_public_key(cert.encode())

    # verify_artifact_signature(signature, public_key, artifact_filepath)
    if not verify_artifact_signature(base64.b64decode(sign.encode()), pub_key, artifact_filepath):
        print("Signature is valid")

    # get_verification_proof(log_index)
    ver_map = get_verification_proof(log_index)

    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    try:
        verify_inclusion(DefaultHasher, ver_map["logIndex"], ver_map["treeSize"], ver_map["leafHash"], ver_map["hashes"], ver_map["rootHash"])
    except Exception as e:
        print(f"In inclusion: Failed to verify consistency with exception {e}")

def get_latest_checkpoint(debug=False):
    res = r.get(CONST_URL)

    if res.status_code == 200:
        return res.json()
    
    else:
        if debug:
            print(f"API call failed with code {res.status_code}")
        return False
    

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        if debug:
            print("prev_checkpoint is empty. Please enter values")
        return False
    
    
    # get_latest_checkpoint()
    root_hash = str(prev_checkpoint["rootHash"])
    tree_size = str(prev_checkpoint["treeSize"])
    tree_id = str(prev_checkpoint["treeID"])

    check_url = f"{CONST_URL}proof?rootHash={root_hash}&lastSize={tree_size}&treeID={tree_id}"
    res = r.get(check_url)

    if res.status_code == 200:
        old_proof = res.json()

    new_proof = get_latest_checkpoint()

    verify_consistency(DefaultHasher, prev_checkpoint["treeSize"], new_proof["treeSize"], old_proof["hashes"], prev_checkpoint["rootHash"], new_proof["rootHash"])

    

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
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
