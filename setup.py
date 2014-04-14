try:
    from setuptools import setup

except:
    from distutils.core import setup

setup(
    name='totalhash-api',
    version='1.0.0',
    packages=['totalhash', 'totalhash.test'],
    url='https://github.com/blacktop/totalhash-api',
    license='GPLv3',
    author='blacktop',
    author_email='',
    description='totalhash - Malware Analysis Database API',
    install_requires=[
        "requests >= 2.2.1",
    ],
)