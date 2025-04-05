# -*- coding: utf-8 -*-

import codecs
import re
import sys

from setuptools import setup


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('aiodns/__init__.py').read()).group('version')


setup(name             = "aiodns",
      version          = get_version(),
      author           = "Saúl Ibarra Corretgé",
      author_email     = "s@saghul.net",
      url              = "https://github.com/saghul/aiodns",
      description      = "Simple DNS resolver for asyncio",
      license          = "MIT",
      long_description = codecs.open("README.rst", encoding="utf-8").read(),
      long_description_content_type = "text/x-rst",
      install_requires = ['pycares>=4.0.0'],
      packages         = ['aiodns'],
      package_data     = {"aiodns": ["py.typed"]},
      platforms        = ["POSIX", "Microsoft Windows"],
      python_requires  = ">=3.9",
      classifiers      = [
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX",
          "Operating System :: Microsoft :: Windows",
          "Programming Language :: Python",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.9",
          "Programming Language :: Python :: 3.10",
          "Programming Language :: Python :: 3.11",
          "Programming Language :: Python :: 3.12",
          "Programming Language :: Python :: 3.13"
      ]
)
