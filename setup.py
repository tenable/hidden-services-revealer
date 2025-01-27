from setuptools import setup, find_packages

setup(
    name="jenganizer",
    version="0.1.1",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "click",
        "click-log",
        "colorlog"
    ],
    entry_points={
        "console_scripts": [
            "jenganizer = jenganizer.jenganizer:cli",
        ],
    },
)
