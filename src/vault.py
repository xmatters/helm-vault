#!/usr/bin/env python3
"""Vault plugin for Helm.

Originlly created by Just-Insane.

Used to process helm yaml files and automatically recover vault secrets to replace templated place holders at helm runtime

See README.md for more info
"""

import argparse
import glob
import json
import os
import platform
import re
import subprocess
import sys

import hvac
import ruamel.yaml

RawTextHelpFormatter = argparse.RawTextHelpFormatter

check_call = subprocess.check_call


if sys.version_info[:2] < (3, 7):
    raise Exception("Python 3.7 or a more recent version is required.")


def parse_args(args):
    """Parse command line arguments.

    Inputs
        args - (dict) CLI args passed into application

    Returns
        parsed args as a dict
    """
    # Help text
    parser = argparse.ArgumentParser(
        description="""Store secrets from Helm in Vault
        \n
        Requirements:
        \n
        Environment Variables:
        \n
        VAULT_ADDR:     (The HTTP address of Vault, for example, http://localhost:8200)
        VAULT_TOKEN:    (The token used to authenticate with Vault)
        """, formatter_class=RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Decrypt help
    decrypt = subparsers.add_parser("dec", help="Parse a YAML file and retrieve values from Vault")
    decrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    decrypt.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    decrypt.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    decrypt.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    decrypt.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")
    decrypt.add_argument("-e", "--environment", type=str, help="Allows for secrets to be decoded on a per environment basis")

    # Clean help
    clean = subparsers.add_parser("clean", help="Remove decrypted files (in the current directory)")
    clean.add_argument("-f", "--file", type=str, help="The specific YAML file to be deleted, without .dec", dest="yaml_file")
    clean.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")
    clean.add_argument("-e", "--environment", type=str, help="Decoded environment to clean")

    # View Help
    view = subparsers.add_parser("view", help="View decrypted YAML file")
    view.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    view.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    view.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    view.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    view.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # Edit Help
    edit = subparsers.add_parser("edit", help="Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.")
    edit.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    edit.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    edit.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    edit.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    edit.add_argument("-ed", "--editor", help="Editor name. Default: (Linux/MacOS) \"vi\" (Windows) \"notepad\"", const=True, nargs="?")
    edit.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # Install Help
    install = subparsers.add_parser("install", help="Wrapper that decrypts YAML files before running helm install")
    install.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    install.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    install.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    install.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    install.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")
    install.add_argument("-e", "--environment", type=str, help="Environment whose secrets to use")

    # Template Help
    template = subparsers.add_parser("template", help="Wrapper that decrypts YAML files before running helm install")
    template.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    template.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    template.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    template.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    template.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # Upgrade Help
    upgrade = subparsers.add_parser("upgrade", help="Wrapper that decrypts YAML files before running helm install")
    upgrade.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    upgrade.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    upgrade.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    upgrade.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    upgrade.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # Lint Help
    lint = subparsers.add_parser("lint", help="Wrapper that decrypts YAML files before running helm install")
    lint.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    lint.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    lint.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    lint.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    lint.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # Diff Help
    diff = subparsers.add_parser("diff", help="Wrapper that decrypts YAML files before running helm diff")
    diff.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    diff.add_argument("-vt", "--vaulttemplate", type=str, help="Prefix to dictate a vault lookup is required. Default: \"VAULT\"")
    diff.add_argument("-mp", "--mountpoint", type=str, help="The Vault Mount Point Default: \"secrets\"")
    diff.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    diff.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    return parser


class Envs(object):
    """Vault control object."""

    def __init__(self, args):
        """Object initialization.

        Inputs
            args - (dict) CLI arguements
        """
        self.args = args
        self.vault_addr = os.environ["VAULT_ADDR"]
        self.vault_mount_point = self.get_env("VAULT_MOUNT_POINT", "mountpoint", "secrets")
        self.secret_template = self.get_env("SECRET_TEMPLATE", "vaulttemplate", "VAULT")
        self.kvversion = self.get_env("KVVERSION", "kvversion", "v2")
        self.environment = self.get_env("NONE", "environment", "")

        if platform.system() != "Windows":
            editor_default = "vi"
        else:
            editor_default = "notepad"

        self.editor = self.get_env("EDITOR", "edit", editor_default)

    def get_env(self, environment_var_name, arg_name, default_value):
        """Fetch env var unless provided by CLI args.

        Inputs
            environment_var_name - (str) the env var to lookup
            arg_name             - (str) the arg value it check for
            default_value        - (str) the default vault if neither env var or arg is set

        Returns
            a string of either the arg value, ENV var, or default value in that order
        """
        value = None

        if environment_var_name in os.environ:
            value = os.environ[environment_var_name]
            source = "ENVIRONMENT"

        if hasattr(self.args, arg_name):
            v = getattr(self.args, arg_name)
            if v:
                value = v
                source = "ARG"

        if value is None and default_value is not None:
            value = default_value
            source = "DEFAULT"

        if self.args.verbose is True:
            print(f"The {source} {arg_name} is: {value}")

        return value


class Vault(object):
    """Vault control object."""

    def __init__(self, args, envs):
        """Object initialization.

        Inputs
            args - (dict) CLI arguements provided
            envs - (obj) Object of the envs type, contains all the environmnet variables (or defaults) use to manipulate this object
        """
        self.args = args
        self.envs = envs
        self.kvversion = envs.kvversion

        # Setup Vault client (hvac)
        try:
            self.client = hvac.Client(url=self.envs.vault_addr, token=os.environ["VAULT_TOKEN"])
        except KeyError:
            print("Vault not configured correctly, check VAULT_ADDR and VAULT_TOKEN env variables.")
        except Exception as ex:
            print(f"ERROR: {ex}")

    def process_mount_point_path_and_key(self, vault_path):
        """Spring the vault path into the mount_point, object path and key name.

        Inputs
            vault_path - (str) the path as found in the yaml, without the VAULT trigger

        Returns
            the mount_point, object path, and key to be used to recover the secret from vault
        """
        path = vault_path.split(':')[0]
        key = None if len(vault_path.split(':')) < 2 else vault_path.split(':')[1]
        if path.startswith('/'):
            mount_point = path.split('/')[1]
            path = '/'.join(path.split('/')[2:])
        else:
            mount_point = self.envs.vault_mount_point

        return mount_point, path, key

    def vault_read(self, mount_point, path):
        """Recover secret(s) from vault.

        Inputs:
            mount_point - (str) the mount point in vault to use
            path        - (str) the path to the object (including the object) to read from vault

        Returns
            returns all data found in the object as a dictionary
        """
        # Read from Vault, using the correct Vault KV version
        try:
            if self.args.verbose is True:
                print(f"Using KV Version: {self.kvversion}")
                print(f"Attempting to read from url: {self.envs.vault_addr}/v1/{mount_point}/data/{path}")

            if self.kvversion == "v1":
                response = self.client.read(path)
                vault_data = response.get("data", {})
            elif self.kvversion == "v2":
                response = self.client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
                vault_data = response.get("data", {}).get("data", {})
            else:
                raise Exception("Wrong KV Version specified, either v1 or v2")
        except AttributeError as ex:
            raise Exception(f"Vault not configured correctly, check VAULT_ADDR and VAULT_TOKEN env variables. {ex}")
        except Exception as ex:
            raise Exception(f"{ex}")

        return vault_data


def load_yaml(yaml_file):
    """Load the contents of a yaml file.

    Inputs
        yaml_file - (str) the name of the file to open including path

    Returns
        The contents of the yaml file as a dict
    """
    # Load the YAML file
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    with open(yaml_file) as filepath:
        data = yaml.load(filepath)
        return data


def cleanup(args, envs):
    """Cleanup decrypted files.

    Inputs
        args - (dict) CLI arguements
        envs - (obj) Object of the envs type, contains all the environmnet variables (or defaults) use to manipulate this object
    """
    yaml_file = args.yaml_file
    decode_file = '.'.join(filter(None, [yaml_file, envs.environment, 'dec']))
    try:
        os.remove(decode_file)
        if args.verbose is True:
            print(f"Deleted {decode_file}")
            sys.exit()
    except AttributeError:
        for fl in glob.glob("*.dec"):
            os.remove(fl)
            if args.verbose is True:
                print(f"Deleted {fl}")
                sys.exit()
    except Exception as ex:
        print(f"Error: {ex}")
    else:
        sys.exit()


def dict_walker(data, args, envs, helm_path=None):
    """Walk through the loaded dicts looking for the values we want.

    Inputs
        data      - (dict) the data to walk through looking for subsitutions
        args      - (dict) CLI arguements provided
        envs      - (obj) Object of the envs type, contains all the environmnet variables (or defaults) use to manipulate this object
        helm_path - (str) the path in the yaml file currently being processing(default: None)
    """
    environment = f"/{envs.environment}" if envs.environment else ""

    vault = Vault(args, envs)
    if isinstance(data, dict):
        for helm_key, value in data.items():
            if str(value).startswith(envs.secret_template):
                _full_path = ':'.join(value.split(':')[1:]).replace("{environment}", environment)
                mount_point, vault_path, key = vault.process_mount_point_path_and_key(_full_path)
                value = vault.vault_read(mount_point, vault_path)
                if key:
                    value = vault.vault_read(mount_point, vault_path).get(key)
                data[helm_key] = value
            for res in dict_walker(value, args, envs, helm_path=f"{helm_path}/{helm_key}"):
                yield res
    elif isinstance(data, list):
        for item in data:
            for res in dict_walker(item, args, envs, helm_path=f"{helm_path}"):
                yield res


def load_secret(args):
    """Load a secrets file.

    Inputs
        args - (dict) CLI arguements

    Returns
        contents of the secrets file as a dict
    """
    if args.secret_file:
        if not re.search(r'\.yaml\.dec$', args.secret_file):
            raise Exception(f"ERROR: Secret file name must end with \".yaml.dec\". {args.secret_file} was given instead.")
        return load_yaml(args.secret_file)


def main(argv=None):
    """Parse arguments from argparse.

    This is outside of the parse_arg function because of issues returning multiple named values from a function
    """
    parsed = parse_args(argv)
    args, leftovers = parsed.parse_known_args(argv)

    yaml_file = args.yaml_file
    yaml_file_data = load_yaml(yaml_file)

    action = args.action

    envs = Envs(args)

    if action == "clean":
        cleanup(args, envs)

    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True

    for res in dict_walker(yaml_file_data, args, envs):
        print(f"Done {res}")

    decode_file = '.'.join(filter(None, [yaml_file, envs.environment, 'dec']))

    if action == "dec":
        yaml.dump(yaml_file_data, open(decode_file, "w"))
        print("Done Decrypting")
    elif action == "view":
        yaml.dump(yaml_file_data, sys.stdout)
    elif action == "edit":
        yaml.dump(yaml_file_data, open(decode_file, "w"))
        os.system(envs.editor + ' ' + f"{decode_file}")
    # These Helm commands are only different due to passed variables
    elif (action == "install") or (action == "template") or (action == "upgrade") or (action == "lint") or (action == "diff"):
        yaml.dump(yaml_file_data, open(decode_file, "w"))
        leftovers = ' '.join(leftovers)

        try:
            cmd = f"helm {args.action} {leftovers} -f {decode_file}"
            if args.verbose is True:
                print(f"About to execute command: {cmd}")
            subprocess.run(cmd, shell=True)
        except Exception as ex:
            print(f"Error: {ex}")

        cleanup(args, envs)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"ERROR: {ex}")
    except SystemExit:
        pass
