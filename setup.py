#!/usr/bin/env python
from distutils.core import setup

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

setup(
    name='asymmetric_jwt_auth',
    version='0.2.0',
    description='Asymmetric key based authentication for HTTP APIs',
    long_description=open('README.rst').read(),
    author='Craig Weber',
    author_email='crgwbr@gmail.com',
    url='https://github.com/crgwbr/asymmetric_jwt_auth',
    packages=packages,
    install_requires=requires,
    license='LICENSE.md'
)
