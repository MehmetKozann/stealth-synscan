from setuptools import setup, find_packages

setup(
    name="synscan",
    version="1.0.0",
    description="Stealth TCP SYN (half-open) port scanner in Python",
    author="Mehmet Kozan",
    packages=find_packages(),
    py_modules=["synscan"],
    entry_points={
        "console_scripts": [
            "synscan=synscan.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
