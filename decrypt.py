from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def desencriptar_AES(nonce, ciphertext, tag, clave):
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)
    mensaje = cipher.decrypt_and_verify(ciphertext, tag)
    return mensaje

if __name__ == "__main__":

    mensaje_desencriptado = desencriptar_AES( b'\rR5\xe7?\x98\xa5I\x94o\xe8\xa0\xb5W3\xac', b'\x13d\x9b{\xa0\xba9\xe9\r\x9b\x1e+\r\x91\xd7n\xf2\xf7N\x98\x88\x06\x89\x13\xea\xa4\xbac,5\xfbX\xa3\xf8\xca\xbd\x93\xba\xfdJ', b'B?\x85\x0bv\x7f\x03\xf4\xe1\x8bn\x9d\xe2:(\x9b', clave=b'sdhashdbj2d712dg')
    print(f"Texto desencriptado: {mensaje_desencriptado}")