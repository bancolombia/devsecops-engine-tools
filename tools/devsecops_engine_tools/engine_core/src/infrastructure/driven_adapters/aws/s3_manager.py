from devsecops_engine_tools.engine_core.src.domain.model.gateway.metrics_manager_gateway import (
    MetricsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.aws import (
    assume_role,
)
import boto3
import logging
import datetime

boto3.set_stream_logger(name="botocore.credentials", level=logging.WARNING)


class S3Manager(MetricsManagerGateway):

    def _get_s3_data(self, client, bucket, path):
        try:
            response = client.get_object(
                Bucket=bucket,
                Key=path,
            )
            return response["Body"].read().decode("utf-8")
        except client.exceptions.NoSuchKey:
            return ""

    def send_metrics(self, config_tool, module, file_path):
        credentials_role = assume_role(config_tool["METRICS_MANAGER"]["AWS"]["ROLE_ARN"]) if config_tool["METRICS_MANAGER"]["AWS"]["USE_ROLE"] else None
        session = boto3.session.Session()

        if credentials_role:
            client = session.client(
                service_name="s3",
                region_name=config_tool["METRICS_MANAGER"]["AWS"]["REGION_NAME"],
                aws_access_key_id=credentials_role["AccessKeyId"],
                aws_secret_access_key=credentials_role["SecretAccessKey"],
                aws_session_token=credentials_role["SessionToken"],
            )
        else:
            client = session.client(
                service_name="s3",
                region_name=config_tool["METRICS_MANAGER"]["AWS"]["REGION_NAME"]
            )
        date = datetime.datetime.now()
        path_bucket = f'engine_tools/{module}/{date.strftime("%Y")}/{date.strftime("%m")}/{date.strftime("%d")}/{file_path.split("/")[-1]}'

        data = self._get_s3_data(
            client, config_tool["METRICS_MANAGER"]["AWS"]["BUCKET"], path_bucket
        )

        with open(file_path, "rb") as new_data:
            new_data_content = new_data.read().decode("utf-8")
            data = data + "\n" + new_data_content if data else new_data_content
            client.put_object(
                Bucket=config_tool["METRICS_MANAGER"]["AWS"]["BUCKET"],
                Key=path_bucket,
                Body=data,
            )
