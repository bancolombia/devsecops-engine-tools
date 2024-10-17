import os
import tempfile
from unittest.mock import patch, call
from unittest import mock

from devsecops_engine_tools.engine_utilities.ssh.managment_private_key import (
    decode_base64,
    config_knowns_hosts,
    create_ssh_private_file,
    add_ssh_private_key,
)


def test_decode_base64():
    result = decode_base64("c2VjcmV0MQ==")
    assert result == "secret1"


@patch("builtins.print")
def test_config_knowns_hosts(mock_print):
    known_hosts_file_path = "~/.ssh/known_hosts"
    host = "example.com"
    ssh_key = "ssh-rsa ABCD1234"

    config_knowns_hosts(host, ssh_key)

    mock_print.mocked_print.mock_calls == [call('"File known_hosts configured sucessfull."')]


def test_create_ssh_private_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        ssh_key_file_path = os.path.join(temp_dir, "test_key")
        ssh_key_content = "private_key_content"
        create_ssh_private_file(ssh_key_file_path, ssh_key_content)

        with open(ssh_key_file_path, "r") as file:
            content = file.read()
            assert content == ssh_key_content


def test_add_ssh_private_key():
    ssh_key_file_path = "/path/to/ssh/key"
    ssh_key_password = "password"
    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

    assert agent_env == None
