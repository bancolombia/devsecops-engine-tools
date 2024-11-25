from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.aws import (
    assume_role
)
import boto3
import json
from botocore.exceptions import NoCredentialsError
import logging
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

boto3.set_stream_logger(name="botocore.credentials", level=logging.WARNING)
logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class SecretsManager(SecretsManagerGateway):
    def get_secret(self, config_tool):
        credentials_role = assume_role(config_tool["SECRET_MANAGER"]["AWS"]["ROLE_ARN"]) if config_tool["SECRET_MANAGER"]["AWS"]["USE_ROLE"] else None
        session = boto3.session.Session()

        if credentials_role:
            client = session.client(
                service_name="secretsmanager",
                region_name=config_tool["SECRET_MANAGER"]["AWS"]["REGION_NAME"],
                aws_access_key_id=credentials_role["AccessKeyId"],
                aws_secret_access_key=credentials_role["SecretAccessKey"],
                aws_session_token=credentials_role["SessionToken"],
            )
        else:
            client = session.client(
                service_name="secretsmanager",
                region_name=config_tool["SECRET_MANAGER"]["AWS"]["REGION_NAME"],
            )

        try:
            secret_name = config_tool["SECRET_MANAGER"]["AWS"]["SECRET_NAME"]
            get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            secret = get_secret_value_response["SecretString"]
            secret_dict = json.loads(secret)
            return secret_dict
        except NoCredentialsError as e:
            logger.error(f"Error getting secret: {e}")
            return None
