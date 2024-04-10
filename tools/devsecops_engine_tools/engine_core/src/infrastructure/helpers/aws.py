import boto3

def assume_role(role_arn):
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="DevSecOpsTools"
    )
    temporal_credentials = response["Credentials"]
    return temporal_credentials