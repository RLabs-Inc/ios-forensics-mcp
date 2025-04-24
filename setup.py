from setuptools import setup, find_packages

setup(
    name="ios_forensics_mcp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "modelcontextprotocol",
        "biplist",
        "python-magic",
        "pillow",
    ],
    entry_points={
        'console_scripts': [
            'ios-forensics-mcp=ios_forensics_mcp.server:main',
        ],
    },
    python_requires=">=3.11",
)