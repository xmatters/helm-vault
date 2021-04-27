"""Setup file for helm vault plugin."""
from setuptools import setup

setup(
    name='vault',
    version='0.5.0',
    description='Helm plugin for storing secrets in HashiCorp Vault',
    author='xMatters',
    author_email='jbresciani@xmatters.com',
    install_requires=['pyyaml', 'hvac'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "LICENSE :: OSI APPROVED :: GNU GENERAL PUBLIC LICENSE V3 (GPLV3)",
        "Operating System :: OS Independent",
    ],
)
