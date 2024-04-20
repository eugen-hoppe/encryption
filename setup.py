from setuptools import setup, find_packages


setup(
    name='iokeys',
    version='0.4.4',
    author='Eugen Hoppe',
    author_email='rispe_keller0x@icloud.com',
    description='Light cryptography encryption functionalities',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/eugen-hoppe/encryption',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
    install_requires=[
        'cryptography==42.0.5'
    ],
    package_data={},
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'iokeys=iokeys.core:main',
        ],
    }
)
