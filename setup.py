from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mcp-security-scanner",
    version="1.0.0",
    author="MCP Security Team",
    author_email="security@mcp.dev",
    description="A comprehensive security scanner for Model Context Protocol (MCP) servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcp/security-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "mcp-scanner=mcp_scanner.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "mcp_scanner": ["config/*.yml", "config/*.yaml"],
    },
)
