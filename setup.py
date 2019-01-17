# -*- coding: utf-8 -*-

import codecs
import re
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('aiodns/__init__.py').read()).group('version')


setup(name             = "aiodns",
      version          = get_version(),
      author           = "Saúl Ibarra Corretgé",
      author_email     = "s@saghul.net",
      url              = "http://github.com/saghul/aiodns",
      description      = "Simple DNS resolver for asyncio",
      long_description = codecs.open("README.rst", encoding="utf-8").read(),
      install_requires = ['pycares>=1.0.0', 'typing'],
      extras_require   = {
          ':python_version=="3.3"': ['asyncio'],
          ':python_version<="3.2"': ['trollius'],
      },
      packages         = ['aiodns'],
      platforms        = ["POSIX", "Microsoft Windows"],
      classifiers      = [
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX",
          "Operating System :: Microsoft :: Windows",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.0",
          "Programming Language :: Python :: 3.1",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7"
      ]
)
