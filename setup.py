#!/usr/bin/env python
from setuptools import setup
import codecs
import os.path

packages = [
    'asymmetric_jwt_auth',
    'asymmetric_jwt_auth.test',
    'asymmetric_jwt_auth.management',
    'asymmetric_jwt_auth.management.commands',
    'asymmetric_jwt_auth.migrations',
]

requires = [
    'PyJWT>=1.4.0',
    'cryptography>=1.0',
]

def fpath(name):
    return os.path.join(os.path.dirname(__file__), name)

def read(fname):
    return codecs.open(fpath(fname), encoding='utf-8').read()

setup(
    name='asymmetric_jwt_auth',
    version='0.2.4',
    description='Asymmetric key based authentication for HTTP APIs',
    long_description=read(fpath('README.rst')),
    author='Craig Weber',
    author_email='crgwbr@gmail.com',
    url='https://github.com/crgwbr/asymmetric_jwt_auth',
    packages=packages,
    install_requires=requires,
    license='LICENSE.md'
)
