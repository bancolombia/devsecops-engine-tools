import boto3
import os

def assume_role(role_arn):
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="DevSecOpsTools"
    )
    temporal_credentials = response["Credentials"]
    return temporal_credentials

def validate_execution_account(different_account):
    return os.environ["AZP_POOL"] in different_account