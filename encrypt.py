from Crypto.Cipher import AES
import sys
import argparse

def encriptar_AES(mensaje, clave):
    cipher = AES.new(clave, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(mensaje)
    print(f"nonce: {cipher.nonce}\
           ciphertext: {ciphertext}\
           tag: {tag}"
           )
    return cipher.nonce, ciphertext, tag

def get_inputs_from_cli_resource_owner(args):
    parser = argparse.ArgumentParser(description="Parse OAUTH ARGS")
    parser.add_argument("-cid", "--client_id", required=True, help="CLIENT ID")
    parser.add_argument("-cs", "--client_secret", required=True, help="CLIENT SECRET")
    parser.add_argument("-tid", "--tenant_id", required=True, help="TENANT ID")
    parser.add_argument("-user", "--username", required=False, help="username ambientes bc")
    parser.add_argument("-pss", "--password", required=False, help="password")

    args, unknown_args = parser.parse_known_args()
    config = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant_id": args.tenant_id,
        "username": args.username,
        "password": args.password
    }

    return config

def get_key(args):

    parser = argparse.ArgumentParser(description="Parse OAUTH ARGS")
    parser.add_argument("-key", "--key_encrypt", required=True, help="ENCRYPT KEY")
    args, unknown_args = parser.parse_known_args()
    key =  args.key_encrypt
    return key

if __name__ == "__main__":


    config = get_inputs_from_cli_resource_owner(sys.argv[1:])
    key = get_key(sys.argv[1:])

    for elem in config.items():
        print(elem[0])
        encriptar_AES(elem[1].encode(), key.encode())
        print()
