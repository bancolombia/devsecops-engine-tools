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
    def send_metrics(self, config_tool, tool, file_path):
        temp_credentials = assume_role(config_tool["METRICS_MANAGER"]["AWS"]["ROLE_ARN"])
        session = boto3.session.Session()
        client = session.client(
            service_name="s3",
            region_name=config_tool["METRICS_MANAGER"]["AWS"]["REGION_NAME"],
            aws_access_key_id=temp_credentials["AccessKeyId"],
            aws_secret_access_key=temp_credentials["SecretAccessKey"],
            aws_session_token=temp_credentials["SessionToken"],
        )
        data = ""
        date = datetime.datetime.now()
        path_bucket = f'{tool}/{date.strftime("%Y")}/{date.strftime("%m")}/{date.strftime("%d")}/{file_path.split("/")[-1]}'
        try:
            response = client.get_object(
                Bucket=config_tool["METRICS_MANAGER"]["AWS"]["BUCKET"],
                Key=path_bucket,
            )
            data = response["Body"].read().decode("utf-8")
        except client.exceptions.NoSuchKey:
            pass

        with open(file_path, "rb") as new_data:
            if data != "":
                data = data + "\n" + new_data.read().decode("utf-8")
            else:
                data = new_data.read().decode("utf-8")
            client.put_object(
                Bucket=config_tool["METRICS_MANAGER"]["AWS"]["BUCKET"],
                Key=path_bucket,
                Body=data,
            )
