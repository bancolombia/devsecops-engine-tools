from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encriptar_AES(mensaje, clave):
    cipher = AES.new(clave, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(mensaje)
    return cipher.nonce, ciphertext, tag

def desencriptar_AES(nonce, ciphertext, tag, clave):
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)
    mensaje = cipher.decrypt_and_verify(ciphertext, tag)
    return mensaje

if __name__ == "__main__":

    clave = get_random_bytes(16)
    mensaje = b"Texto a encriptar"

    nonce, ciphertext, tag = encriptar_AES(mensaje, clave)
    print(f"Texto encriptado: {ciphertext}\
          nonce: {nonce}\
          tag: {tag}\
          clave: {clave}")


    mensaje_desencriptado = desencriptar_AES(nonce, ciphertext, tag, clave)
    print(f"Texto desencriptado: {mensaje_desencriptado}")
