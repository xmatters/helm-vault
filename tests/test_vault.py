"""Unit Tests for the Helm-vault plugin."""
import os
import subprocess
from base64 import b64encode
from shutil import copyfile
from unittest import TestCase

import hvac
import src.vault as vault
import yaml


class helmVaultTests(TestCase):
    """Unit tests."""

    def setUp(self):
        """Init for test environment."""
        os.environ["KVVERSION"] = "v2"
        self.mount_path = "secret"
        self.secret_path = "hello"
        self.secret = {
            "value": "testsecret",
            "custom.key": "customSecret"
        }
        self.expected_data = {
            "secrets": {
                "stringData": {
                    "unencoded-value": "VAULT:/secret/hello:value",
                    "unencoded-custom.key": "VAULT:/secret/hello:custom.key"
                },
                "data": "VAULT:/secret/hello"
            }
        }
        self.expected_decoded_data = {
            "secrets": {
                "stringData": {
                    "unencoded-value": self.secret["value"],
                    "unencoded-custom.key": self.secret["custom.key"]
                },
                "data": {
                    "custom.key": self.secret["custom.key"],
                    "value": self.secret["value"]
                }
            }
        }
        self.expected_rendered_template = {
            "kind": "Secret",
            "apiVersion": "v1",
            "stringData": {
                "unencoded-custom.key": self.secret["custom.key"],
                "unencoded-value": self.secret["value"]
            },
            "data": {
                "custom.key": b64encode(self.secret["custom.key"].encode()).decode('utf-8'),
                "value": b64encode(self.secret["value"].encode()).decode('utf-8')
            }
        }
        self.test_yaml_file = "./tests/test.yaml"
        self.client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
        self.client.secrets.kv.v2.create_or_update_secret(
            path=self.secret_path,
            secret=self.secret,
            mount_point=self.mount_path
        )
        secret_version_response = self.client.secrets.kv.v2.read_secret_version(
            path=self.secret_path,
            mount_point=self.mount_path
        )
        secrets = secret_version_response.get("data", {}).get("data", {})
        assert secrets == self.secret

    def tearDown(self):
        """Tear down after tests complete."""
        self.client.session.close()

    def test_load_yaml(self):
        """Test loading data from a yaml file."""
        loaded_data = vault.load_yaml(self.test_yaml_file)
        self.assertDictEqual(loaded_data, self.expected_data)

    def test_parser(self):
        """Test command parser."""
        copyfile("./tests/test.yaml", "./tests/test.yaml.bak")
        parser = vault.parse_args(['clean', '-f ./tests/test.yaml'])
        self.assertTrue(parser)
        copyfile("./tests/test.yaml.bak", "./tests/test.yaml")
        os.remove("./tests/test.yaml.bak")

    def test_dec(self):
        """Test decoding of yaml."""
        vault.main(['dec', './tests/test.yaml'])
        self.assertTrue(self.client.is_authenticated())
        decoded_data = vault.load_yaml(f"{self.test_yaml_file}.dec")
        self.assertDictEqual(decoded_data, self.expected_decoded_data)

    def test_install(self):
        """Test helm-vault."""
        plugin_list = subprocess.run(["helm", "plugin", "list"], stdout=subprocess.PIPE)
        if "vault" not in plugin_list.stdout.decode('utf-8'):
            subprocess.run(["helm", "plugin", "install", "./"])
        result = subprocess.run(["helm", "vault", "template", "--namespace=test-namespace", "vault-test", "./tests/helm/test", "-f", "./tests/test.yaml"], stdout=subprocess.PIPE)
        rendered_template = yaml.safe_load(result.stdout)
        self.assertDictEqual(rendered_template, self.expected_rendered_template)
