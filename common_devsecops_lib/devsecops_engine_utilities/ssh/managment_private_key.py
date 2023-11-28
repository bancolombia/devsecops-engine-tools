import os
import pexpect
import platform
import base64

def decode_base64 (secret_data,key_name):

    key_name_secret = secret_data[key_name]

    secreto_decodificado = base64.b64decode(key_name_secret).decode('utf-8')
    return secreto_decodificado

def create_ssh_private_file(ssh_key_file_path, ssh_key_content):
    try:
        with open(ssh_key_file_path, "w") as archivo:
            archivo.write(ssh_key_content)
        permisos = 0o600

        os.chmod(ssh_key_file_path, permisos)
        print("File create sucessfull.")
    except Exception as e:
        print(f"An error ocurred creating file: {e}")


def add_ssh_private_key(ssh_key_file_path, ssh_key_password):
    try:
        if platform.system() != 'Linux':
            raise Exception("Este script solo es compatible con sistemas Linux")
        
        # Iniciar un nuevo shell y evaluar el comando ssh-agent
        comando_ssh_agent = "eval $(ssh-agent -s)"
        proceso_shell = pexpect.spawn("/bin/bash", ["-c", comando_ssh_agent])

        # Esperar a que se complete la inicialización de ssh-agent
        proceso_shell.expect(pexpect.EOF)

        # Agregar la clave privada al ssh-agent proporcionando la contraseña
        proceso_sshadd = pexpect.spawn(f"ssh-add {ssh_key_file_path}" )

        # Esperar la solicitud de contraseña y proporcionarla
        proceso_sshadd.expect("Enter passphrase", timeout=5)
        proceso_sshadd.sendline(ssh_key_password)

        # Esperar a que se complete la operación
        proceso_sshadd.expect(pexpect.EOF)

        print("Private key add sucessfull.")
    except Exception as e:
        print(f"An error ocurred adding private key: {e}")