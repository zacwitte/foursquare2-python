"""Installer for foursquare"""

try:
        from setuptools import setup, find_packages
except ImportError:
        from ez_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages
setup(
    name='Foursquare',
    description='Python module to interface with the foursquare API v2',
    version='0.2',
    author='Zac Witte',
    author_email='zacwitte@gmail.com',
    url='https://github.com/zacwitte/foursquare2-python',
    packages=find_packages(exclude=('ez_setup', 'tests',)),
    license=open('LICENSE.txt').read()
)
