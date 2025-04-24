from setuptools import setup, find_packages

setup(
    name="ios_forensics_mcp",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "mcp[cli]>=1.6.0",
        "biplist",
        "python-magic",
        "pillow",
    ],
    entry_points={
        'console_scripts': [
            'ios-forensics-mcp=ios_forensics_mcp:main',
        ],
    },
    python_requires=">=3.11",
)