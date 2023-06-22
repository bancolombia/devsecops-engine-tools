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
        "defect_dojo",
        "devsecops_engine_utilities",
        "devsecops_engine_utilities.azuredevops",
        "devsecops_engine_utilities.azuredevops.infrastructure",
        "devsecops_engine_utilities.azuredevops.models",
        "devsecops_engine_utilities.github",
        "devsecops_engine_utilities.github.infrastructure",
        # "devsecops_engine_utilities.github.models", "no hay module"
        "devsecops_engine_utilities.input_validations",
        "devsecops_engine_utilities.utils",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'multipledispatch==0.6.0',
        'pyfiglet==0.7',
        'setuptools==67.6.0',
        'wheel==0.40.0',
        'pipenv==2023.3.20',
        'pytest==7.3.1',
        'pytest-azurepipelines==1.0.3',
        'pytest-cov==4.1.0',
        'coverage==7.2.7',
        'requests==2.28.2',
        'mock==5.0.2',
        'marshmallow==3.19.0',
        'requests-toolbelt==1.0.0',
        'isodate==0.6.1',
        'pytz==2023.3',
        'python-dateutil==2.8.2',
        ],
    python_requires=">=3.8",
)
