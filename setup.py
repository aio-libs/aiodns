# -*- coding: utf-8 -*-

import re
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('aiodns/__init__.py').read()).group('version')

install_requires = ['pycares']
if sys.version_info < (3, 4):
    install_requires.append('asyncio')

setup(name             = "aiodns",
      version          = get_version(),
      author           = "Saúl Ibarra Corretgé",
      author_email     = "saghul@gmail.com",
      url              = "http://github.com/saghul/aiodns",
      description      = "Simple DNS resolver for asyncio",
      long_description = open("README.rst").read(),
      install_requires = install_requires,
      packages         = ['aiodns'],
      platforms        = ["POSIX", "Microsoft Windows"],
      classifiers      = [
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX",
          "Operating System :: Microsoft :: Windows",
          "Programming Language :: Python",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4"
      ]
)

