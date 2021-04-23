#!/usr/bin/env python3

import os

import hvac


class Vault:
    def __init__(self):
        self.mount_path = "secret"
        self.secret_path = "hello"
        self.secret = {
            "value": "testsecret",
            "custom.key": "testsecret2"
        }
        self.client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])


    def vault_write(self):
        self.client.secrets.kv.v2.create_or_update_secret(
            path=self.secret_path,
            secret=self.secret,
            mount_point=self.mount_path
        )

    def vault_read(self):
        secret_version_response = self.client.secrets.kv.v2.read_secret_version(
            path=self.secret_path,
            mount_point=self.mount_path
        )
        secrets = secret_version_response.get("data", {}).get("data", {})
        assert secrets == self.secret


def test_main():
    vault = Vault()
    vault.vault_write()
    vault.vault_read()
