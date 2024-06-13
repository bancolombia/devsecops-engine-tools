from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list


def validateConditionPrincipalARN(statement):
    res = False
    if "Condition" in statement:
        condition = statement["Condition"]
        if "StringLike" in condition:
            stringLike = condition["StringLike"]
            if "aws:PrincipalArn" in stringLike:
                res = True
    return res


def validateRolesNotApply(principal):
    res = False
    if "cloudformation-service-deployment-role-vsts" in principal or "devops-daticalsecrets" in principal or "AWSServiceRoleForAmazonMacie" in principal or "sftp" in principal.lower():
        res = True
    return res

def validateSidEncryptData(statement):
    res = False
    if "Sid" in statement and "Principal" in statement:
        sid = statement["Sid"]
        principal = statement["Principal"]
        if "Allow encrypt and decrypt data" in sid and "RootRole" in str(principal):
            res = True
    return res


class KMSKeyWildCardPrincipal(BaseResourceCheck):
    def __init__(self):
        name = "Ensure KMS key policy is configured with minimum privilege"
        id = "CKV_AWS_264"
        supported_resources = ['AWS::KMS::Key']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if conf.get('Properties'):
            if conf['Properties'].get('KeyPolicy'):
                policy_block = conf['Properties']['KeyPolicy']
                if policy_block and isinstance(policy_block, dict) and 'Statement' in policy_block.keys():
                    for statement in force_list(policy_block['Statement']):
                        if 'Principal' in statement:
                            principal = statement['Principal']
                            if "root" in str(principal) or "Service" in principal or validateRolesNotApply(str(principal)):
                                continue
                            if 'Effect' in statement:
                                if statement['Effect'] == "Deny":
                                    continue
                            if 'AWS' in principal:
                                aws_principals = principal['AWS']
                                if aws_principals == "*" and validateConditionPrincipalARN(statement):
                                    continue
                                if isinstance(aws_principals, list):
                                    for principal_index, principal in enumerate(aws_principals):
                                        if principal == "*":
                                            return CheckResult.FAILED
                            if 'Action' in statement:
                                action = force_list(
                                    statement.get('Action', ['']))
                                if isinstance(action, list):
                                    for action_value in action:
                                        if action_value == '*' or action_value == 'kms:*':
                                            return CheckResult.FAILED
                                else:
                                    if action == '*' or action == 'kms:*':
                                        return CheckResult.FAILED
                            if validateSidEncryptData(statement):
                                continue     
                            if "Condition" in statement:
                                condition = statement["Condition"]
                                if "StringEquals" in condition:
                                    stringEquals = condition["StringEquals"]
                                    if "kms:ViaService" not in stringEquals:
                                        return CheckResult.FAILED
                                else:
                                    return CheckResult.FAILED
                            else:
                                return CheckResult.FAILED

                    return CheckResult.PASSED


check = KMSKeyWildCardPrincipal()
