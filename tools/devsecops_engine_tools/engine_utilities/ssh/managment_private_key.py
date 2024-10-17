import os
import pexpect
import base64


def decode_base64(secret_data):
    return base64.b64decode(secret_data).decode("utf-8")


def config_knowns_hosts(host, ssh_key):
    try:
        ssh_directory = os.path.expanduser("~/.ssh")
        if not os.path.exists(ssh_directory):
            os.makedirs(ssh_directory)

        known_hosts_file_path = os.path.expanduser("~/.ssh/known_hosts")
        line_to_add = f"{host} ssh-rsa {ssh_key}\n"
        if not os.path.exists(known_hosts_file_path):
            with open(known_hosts_file_path, "w") as known_hosts_file:
                known_hosts_file.write(line_to_add)
        else:
            with open(known_hosts_file_path, "a") as known_hosts_file:
                known_hosts_file.write(line_to_add)
    except Exception as e:
        print(f"An error ocurred while configuring file: {e}")


def create_ssh_private_file(ssh_key_file_path, ssh_key_content):
    try:
        with open(ssh_key_file_path, "w") as archivo:
            archivo.write(ssh_key_content)
        permisos = 0o600

        os.chmod(ssh_key_file_path, permisos)
    except Exception as e:
        print(f"An error ocurred creating file: {e}")


def add_ssh_private_key(ssh_key_file_path, ssh_key_password):
    try:
        # Iniciar un nuevo shell y evaluar el comando ssh-agent
        pexpect.spawn("ssh-agent -k")
        ssh_process = pexpect.spawn("ssh-agent -s")
        ssh_process.expect("SSH_AUTH_SOCK=(.*?);")
        ssh_auth_sock = ssh_process.match.group(1).decode()
        ssh_process.expect("SSH_AGENT_PID=(.*?);")
        ssh_agent_pid = ssh_process.match.group(1).decode()

        agent_env = {"SSH_AUTH_SOCK": ssh_auth_sock, "SSH_AGENT_PID": ssh_agent_pid}

        # Esperar a que se complete la inicialización de ssh-agent
        ssh_process.expect(pexpect.EOF)

        # Agregar la clave privada al ssh-agent proporcionando la contraseña
        ssh_add_process = pexpect.spawn(f"ssh-add {ssh_key_file_path}", env=agent_env)

        # Esperar la solicitud de contraseña y proporcionarla
        ssh_add_process.expect("Enter passphrase", timeout=5)
        ssh_add_process.sendline(ssh_key_password)

        # Esperar a que se complete la operación
        ssh_add_process.expect(pexpect.EOF)

        return agent_env
    except Exception as e:
        print(f"An error ocurred adding private key: {e}")
