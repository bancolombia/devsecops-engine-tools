from setuptools import setup, find_packages


def get_readme():
    with open("README.md", "r") as fh:
        return fh.read()


def get_requirements():
    with open("requirements.txt", "r") as fh:
        return fh.read()


setup(
    name="devsecops_engine_tools",
    version="1.7.3",
    author="Bancolombia devsecops Team ",
    author_email="devsecops@bancolombia.com.co",
    description="tool for devsecops strategy",
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/bancolombia/NU0429001_devsecops_engine",
    package_dir={
        "devsecops_engine_tools": "devsecops_engine_tools",
    },
    packages=find_packages(exclude=["**test**"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=get_requirements(),
)
