import setuptools


def get_readme():
    with open("README.md", "r") as fh:
        return fh.read()


def get_requirements():
    with open("requirements.txt", "r") as fh:
        return fh.read()


setuptools.setup(
    name="devsecops_engine_utilities",
    version="0.0.1",
    author="Bancolombia devsecops Team ",
    author_email="devsecops@bancolombia.com.co",
    description="Common utilities tools for engine devsecops",
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/bancolombia/NU0429001_devsecops_engine",
    package_dir={
        "devsecops_engine_utilities": "devsecops_engine_utilities",
    },
    packages=[
        "devsecops_engine_utilities",
        "devsecops_engine_utilities.azuredevops",
        "devsecops_engine_utilities.azuredevops.infrastructure",
        "devsecops_engine_utilities.azuredevops.models",
        "devsecops_engine_utilities.github",
        "devsecops_engine_utilities.github.infrastructure",
        "devsecops_engine_utilities.github.models",
        "devsecops_engine_utilities.input_validations",
        "devsecops_engine_utilities.utils",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=get_requirements(),
    python_requires=">=3.8",
)
