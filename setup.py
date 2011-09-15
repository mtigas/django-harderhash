import os
from setuptools import setup, find_packages

README_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                           'README.rst')

description = 'Make Django use a slow loop of sha384 for hashing passwords.'
long_description = open(README_PATH, 'r').read()

setup(
    name='django-harderhash',
    version='0.1',
    description=description,
    long_description=long_description,
    author='Mike Tigas',
    author_email='mike@tig.as',
    url='https://github.com/mtigas/django-harderhash/',
    packages=['django_harderhash'],
)
