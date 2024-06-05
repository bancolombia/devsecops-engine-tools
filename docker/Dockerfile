FROM alpine@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd
WORKDIR /app

# Setting environment variables
ENV DET_PIPELINE_NAME="Example_devsecops_engine_tools" \
    DET_PATH_DIRECTORY="." \
    DET_OS="Linux" \
    DET_WORK_FOLDER="/Users/user/work" \
    DET_TEMP_DIRECTORY="/tmp" \
    DET_BRANCH_NAME="trunk" \
    DET_SOURCE_CODE_MANAGEMENT_URI="https://github.com/bancolombia/devsecops-engine-tools" \
    DET_BASE_COMPACT_REMOTE_CONFIG_URL="" \
    DET_ACCESS_TOKEN="" \
    DET_BUILD_EXECUTION_ID="2688" \
    DET_BUILD_ID="2688" \
    DET_BRANCH_TAG="refs/heads/trunk" \
    DET_COMMIT_HASH="2d545969a76516156d76e1c88f8e699537e889bd" \
    DET_ENVIRONMENT="dev" \
    DET_STAGE="Release" \
    DET_AGENT_DIRECTORY="" \
    DET_REPOSITORY_PROVIDER="" \
    DET_TARGET_BRANCH="" \
    DET_SOURCE_BRANCH="" \
    DET_ORGANIZATION="" \
    DET_PROJECT_NAME="" \
    DET_REPOSITORY=""

# Container remote config creation
COPY /example_remote_config_local/ /app/example_remote_config_local/
COPY .envdetlocal /app/.env

# Install dependencies for building Python
RUN apk update && \
    apk add --no-cache \
    git \
    build-base \
    libffi-dev \
    openssl-dev \
    bzip2-dev \
    zlib-dev \
    readline-dev \
    sqlite-dev \
    wget \
    xz

# Download and install Python 3.11.8
RUN wget https://www.python.org/ftp/python/3.11.8/Python-3.11.8.tgz && \
    tar -xzf Python-3.11.8.tgz && \
    cd Python-3.11.8 && \
    ./configure --enable-optimizations && \
    make altinstall && \
    cd .. && \
    rm -rf Python-3.11.8 Python-3.11.8.tgz

# Ensure python3 points to the new version
RUN ln -s /usr/local/bin/python3.11 /usr/local/bin/python3 && \
    ln -s /usr/local/bin/pip3.11 /usr/local/bin/pip3

# Create and activate virtual environment
RUN /usr/local/bin/python3.11 -m venv venv
RUN source venv/bin/activate

# Install devsecops-engine-tools
RUN /usr/local/bin/python3.11 -m pip install devsecops-engine-tools==1.7.6

CMD ["source", "venv/bin/activate"]