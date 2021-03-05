#!/usr/bin/env python
from setuptools import setup, find_packages, Distribution
import codecs
import os.path

# Make sure versiontag exists before going any further
Distribution().fetch_build_eggs('versiontag>=1.2.0')

from versiontag import get_version, cache_git_tag  # NOQA


packages = find_packages('src')

install_requires = [
    'PyJWT>=2.0.1',
    'cryptography>=3.4.6',
    'Django>=2.2',
]

extras_require = {
    'development': [
        'coverage>=5.5',
        'django-stubs>=1.7.0',
        'flake8>=3.2.1',
        'freezegun>=1.1.0',
        'mypy>=0.812',
        'sphinx-rtd-theme>=0.5.1',
        'sphinx>=3.5.1',
        'types-cryptography>=0.1.1',
        'typing>=3.7.4.3',
        'versiontag>=1.2.0',
    ],
}


def fpath(name):
    return os.path.join(os.path.dirname(__file__), name)


def read(fname):
    return codecs.open(fpath(fname), encoding='utf-8').read()


cache_git_tag()

setup(
    name='asymmetric_jwt_auth',
    description='Asymmetric key based authentication for HTTP APIs',
    version=get_version(pypi=True),
    long_description=read(fpath('README.rst')),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: Unix',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    author='Craig Weber',
    author_email='crgwbr@gmail.com',
    url='https://github.com/crgwbr/asymmetric-jwt-auth',
    license='ISC',
    package_dir={'': 'src'},
    packages=packages,
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require
)
