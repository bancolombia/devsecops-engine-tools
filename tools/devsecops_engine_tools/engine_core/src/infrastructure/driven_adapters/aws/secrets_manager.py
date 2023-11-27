from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
import boto3
import json
from botocore.exceptions import NoCredentialsError
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)


@dataclass
class SecretsManager(SecretsManagerGateway):
    def get_secret(self, dict_args):
        base_compact_remote_config_url = (
            f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
            f"{dict_args['azure_remote_config_repo']}?path=/resources/ConfigTool.json"
        )
        utils_azure = AzureDevopsApi(
            personal_access_token=SystemVariables.System_AccessToken.value(),
            compact_remote_config_url=base_compact_remote_config_url,
        )
        connection = utils_azure.get_azure_connection()
        config_tool = utils_azure.get_remote_json_config(connection=connection)

        temp_credentials = self.assume_role(
            config_tool["SECRET_MANAGER"]["AWS"]["ROLE_ARN"]
        )
        session = boto3.session.Session()
        client = session.client(
            service_name="secretsmanager",
            region_name=config_tool["SECRET_MANAGER"]["AWS"]["REGION_NAME"],
            aws_access_key_id=temp_credentials["AccessKeyId"],
            aws_secret_access_key=temp_credentials["SecretAccessKey"],
            aws_session_token=temp_credentials["SessionToken"],
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=config_tool["SECRET_MANAGER"]["AWS"]["SECRET_NAME"]
            )
            secret = get_secret_value_response["SecretString"]
            secret_dict = json.loads(secret)
            return secret_dict
        except NoCredentialsError as e:
            print(f"Error: {e}")
            return None

    def assume_role(self, role_arn):
        sts_client = boto3.client("sts")

        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="DevSecOpsTools"
        )

        temporal_credentials = response["Credentials"]

        return temporal_credentials
