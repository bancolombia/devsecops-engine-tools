import os
import tempfile
from unittest.mock import patch
from unittest import mock

from devsecops_engine_utilities.ssh.managment_private_key import (
    decode_base64,
    config_knowns_hosts,
    create_ssh_private_file,
    add_ssh_private_key,
)


def test_decode_base64():
    secret_data = {"key1": "c2VjcmV0MQ==", "key2": "c2VjcmV0Mg=="}
    key_name = "key1"
    result = decode_base64(secret_data, key_name)
    assert result == "secret1"


@mock.patch("platform.system")
def test_config_knowns_hosts(platform_system):
    known_hosts_file_path = "~/.ssh/known_hosts"
    host = "example.com"
    ssh_key = "ssh-rsa ABCD1234"

    platform_system.return_value = "Linux"

    config_knowns_hosts(host, ssh_key)

    assert platform_system.called


def test_create_ssh_private_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        ssh_key_file_path = os.path.join(temp_dir, "test_key")
        ssh_key_content = "private_key_content"
        create_ssh_private_file(ssh_key_file_path, ssh_key_content)

        with open(ssh_key_file_path, "r") as file:
            content = file.read()
            assert content == ssh_key_content


@mock.patch("platform.system")
def test_add_ssh_private_key(platform_system):
    platform_system.return_value = "Linux"

    ssh_key_file_path = "/path/to/ssh/key"
    ssh_key_password = "password"
    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)
    
    assert agent_env == None
