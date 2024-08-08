FROM alpine@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd
WORKDIR /app

# Received args
ARG VERSION
ENV APP_VERSION=$VERSION

ENV DET_PIPELINE_NAME="" \
    DET_PATH_DIRECTORY="." \
    DET_OS="Linux" \
    DET_WORK_FOLDER="" \
    DET_TEMP_DIRECTORY="/tmp" \
    DET_BRANCH_NAME="" \
    DET_SOURCE_CODE_MANAGEMENT_URI="" \
    DET_BASE_COMPACT_REMOTE_CONFIG_URL="" \
    DET_ACCESS_TOKEN="" \
    DET_BUILD_EXECUTION_ID="" \
    DET_BUILD_ID="" \
    DET_BRANCH_TAG="" \
    DET_COMMIT_HASH="" \
    DET_ENVIRONMENT="" \
    DET_STAGE="Release" \
    DET_AGENT_DIRECTORY="" \
    DET_REPOSITORY_PROVIDER="" \
    DET_TARGET_BRANCH="" \
    DET_SOURCE_BRANCH="" \
    DET_ORGANIZATION="" \
    DET_PROJECT_NAME="" \
    DET_REPOSITORY=""

# Container remote config creation
COPY /docker /app/docker_remote_config_local/
COPY .envdetlocal /app/.env

RUN apk update && \
    apk add --no-cache \
    docker \
    openrc \
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

# Enable and start Docker service
RUN rc-update add docker boot

RUN apk add python3
RUN apk add py-pip

# Ensure python3 points to the new version
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python3 && \
    ln -s /usr/local/bin/pip3 /usr/local/bin/pip3

RUN python3 -m venv venv
RUN source venv/bin/activate

RUN python3 -m pip install --break-system-packages -i https://pypi.org/simple devsecops-engine-tools==$APP_VERSION

CMD ["sh", "-c", "dockerd & while ! docker info > /dev/null 2>&1; do sleep 1; done; sh"]