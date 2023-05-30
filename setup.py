import setuptools
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_VERSION


def get_readme():
    with open("README.md", "r") as fh:
        return fh.read()


def get_requirements():
    with open("requirements.txt", "r") as fh:
        return fh.read()


setuptools.setup(
    name="devsecops_engine_sast",
    version=DEVSECOPS_ENGINE_UTILITIES_VERSION,
    author="Bancolombia devsecops Team ",
    author_email="devsecops@bancolombia.com.co",
    description="tool sast for engine devsecops",
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/bancolombia/NU0429001_devsecops_engine",
    package_dir={
        "devsecops_engine_sast": "devsecops_engine_sast",
    },
    packages=[
        "engine_sast",
        "engine_sast.engine_iac",
        "engine_sast.engine_iac.src",
        "engine_sast.engine_iac.src.applications",
        "engine_sast.engine_iac.src.domain",
        "engine_sast.engine_iac.src.domain.model",
        "engine_sast.engine_iac.src.domain.model.gateways",
        "engine_sast.engine_iac.src.domain.usecases",
        "engine_sast.engine_iac.src.infrastructure",
        "engine_sast.engine_iac.src.infrastructure.driven_adapters",
        "engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops",
        "engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool",
        "engine_sast.engine_iac.src.infrastructure.entry_points",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=get_requirements(),
    python_requires=">=3.8",
)
