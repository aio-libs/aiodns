
import re
from invoke import task


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('aiodns/__init__.py').read()).group('version')


@task
def release(c):
    version = get_version()

    c.run("git tag -a aiodns-{0} -m \"aiodns {0} release\"".format(version))
    c.run("git push --tags")

    c.run("python setup.py sdist")
    c.run("twine upload -r pypi dist/aiodns-{0}*".format(version))

