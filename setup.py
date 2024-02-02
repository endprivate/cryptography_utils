from setuptools import setup, find_packages

setup(
    name='crypto_utils',
    version='1.0.0',
    description='A utility package for cryptographic operations',
    author='Your Name',
    author_email='molniya213y@proton.me',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
    ],
)
