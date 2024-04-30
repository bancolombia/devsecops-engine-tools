from setuptools import setup, find_packages
from importlib import util
import os

def get_readme():
    with open("../README.md", "r") as fh:
        return fh.read()


def get_requirements():
    with open("requirements.txt", "r") as fh:
        return [line.strip() for line in fh.readlines()]

spec = util.spec_from_file_location(
    "devsecops_engine_tools.version", os.path.join("devsecops_engine_tools", "version.py")
)
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)
version = mod.version

setup(
    name="devsecops-engine-tools",
    version=version,
    author="Bancolombia DevSecOps Team",
    author_email="devsecops@bancolombia.com.co",
    description="tool for devsecops strategy",
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/bancolombia/devsecops-engine-tools",
    package_dir={
        "devsecops_engine_tools": "devsecops_engine_tools",
    },
    packages=find_packages(exclude=["**test**"]),
    entry_points={
        'console_scripts': [
            'devsecops-engine-tools=devsecops_engine_tools.engine_core.src.applications.runner_engine_core:application_core'
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests==2.31.0",
        "multipledispatch==0.6.0",
        "PyYAML==6.0.1",
        "checkov==2.3.296",
        "pyfiglet==0.7",
        "prettytable==3.8.0",
        "azure-devops==7.1.0b3",
        "marshmallow==3.19.0",
        "pytz==2023.3",
        "python-decouple==3.8",
        "requests_toolbelt==1.0.0",
        "python-dateutil==2.8.2",
        "pexpect==4.9.0"
    ],
)
