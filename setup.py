#!/usr/bin/env python

from SimpleHTTPSAuthUploadServer import __version__, __prog__
from setuptools import setup, find_packages


def _requires_from_file(filename):
    return open(filename).read().splitlines()


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name=__prog__,
    version=__version__,
    description='Simple HTTP and HTTPS Auth and Upload Server',
    author='Kenichi Tanino',
    author_email='tanino@a2.mbn.or.jp',
    long_description=long_description,
    url='https://github.com/KenichiTanino/SimpleHTTPSAuthUploadServer/',
    packages=find_packages(),
    install_requires=_requires_from_file('requirements.txt'),
    entry_points={
        'console_scripts': ['SimpleHTTPSAuthUploadServer = SimpleHTTPSAuthUploadServer.simple_https_auth_upload:main']
    },
    classifiers=[
        "Programming Language :: Python :: 3.4",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.4',
)
