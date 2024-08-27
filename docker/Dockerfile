FROM debian@sha256:aadf411dc9ed5199bc7dab48b3e6ce18f8bbee4f170127f5ff1b75cd8035eb36
WORKDIR /app

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

RUN apt-get update && apt-get install -y bash
RUN apt-get update && apt-get install -y dos2unix

COPY ./example_remote_config_local /app/example_remote_config_local
COPY ./docker/remoteConfigGeneration.sh /app/remoteConfigGeneration.sh

RUN dos2unix /app/remoteConfigGeneration.sh

RUN chmod +x /app/remoteConfigGeneration.sh
RUN /bin/bash remoteConfigGeneration.sh

COPY .envdetlocal /app/.env

RUN apt-get update && \
    apt-get install -y \
    python3-venv \
    python3-pip

RUN ln -s /usr/bin/python3 /usr/local/bin/python3 && \
    ln -s /usr/bin/pip3 /usr/local/bin/pip3

RUN python3 -m venv venv
RUN python3 -m pip install --break-system-packages checkov==2.3.296
RUN python3 -m pip install --break-system-packages -i https://pypi.org/simple devsecops-engine-tools==$APP_VERSION

CMD ["sh", "-c", "dockerd & while ! docker info > /dev/null 2>&1; do sleep 1; done; sh"]