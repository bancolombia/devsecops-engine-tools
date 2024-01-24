from devsecops_engine_tools.engine_core.src.domain.model.gateway.metrics_manager_gateway import (
    MetricsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.aws import (
    assume_role,
    validate_execution_account,
)
import boto3
import logging

boto3.set_stream_logger(name="botocore.credentials", level=logging.WARNING)


class S3Manager(MetricsManagerGateway):
    def send_metrics(self, config_tool, tool, file_path):
        execution_different_account = config_tool["METRICS_MANAGER"]["AWS"][
            "EXECUTION_DIFFERENT_ACCOUNT"
        ]
        temp_credentials = assume_role(
            config_tool["METRICS_MANAGER"]["AWS"]["ROLE_ARN_DIFFERENT_ACCOUNT"]
            if validate_execution_account(execution_different_account)
            else config_tool["METRICS_MANAGER"]["AWS"]["ROLE_ARN"]
        )
        session = boto3.session.Session()
        client = session.client(
            service_name="s3",
            region_name=config_tool["METRICS_MANAGER"]["AWS"]["REGION_NAME"],
            aws_access_key_id=temp_credentials["AccessKeyId"],
            aws_secret_access_key=temp_credentials["SecretAccessKey"],
            aws_session_token=temp_credentials["SessionToken"],
        )

        with open(file_path, "rb") as data:
            bucket = (
                config_tool["METRICS_MANAGER"]["AWS"]["BUCKET_DIFFERENT_ACCOUNT"]
                if validate_execution_account(execution_different_account)
                else config_tool["METRICS_MANAGER"]["AWS"]["BUCKET"]
            )
            client.upload_fileobj(data, bucket, f'{tool}/{file_path.split("/")[-1]}')
