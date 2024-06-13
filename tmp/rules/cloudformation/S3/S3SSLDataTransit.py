from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.type_forcers import force_list


class S3SSLDataTransit(BaseResourceCheck):
    def __init__(self):
        name = "Ensure the S3 bucket policy has ssl data in transit"
        id = "CKV_AWS_292"
        supported_resources = ['AWS::S3::BucketPolicy']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        list = []
        if conf.get('Properties'):
            if conf['Properties'].get('PolicyDocument'):
                policy_block = conf['Properties']['PolicyDocument']
                if policy_block and isinstance(policy_block, dict) and 'Statement' in policy_block.keys():
                    if 'Fn::If' in policy_block['Statement']:
                        list = policy_block['Statement']['Fn::If']
                        result = 0
                        for x in list[1:]:
                            if check_policy(x) == CheckResult.PASSED: result = result + 1
                        if result == 2:
                            return CheckResult.PASSED
                        else:
                            return CheckResult.FAILED
                    else:
                        return check_policy(policy_block['Statement'])


check = S3SSLDataTransit()


def check_policy(policy_block):
    boolCondition = False
    boolPrincipal = False
    boolAction = False
    for statement in force_list(policy_block):
        if 'Effect' in statement:
            if statement['Effect'] == "Deny":
                if "Condition" in statement:
                    condition = statement["Condition"]
                    if "Bool" in condition:
                        bool = condition["Bool"]
                        if "aws:SecureTransport" in bool:
                            if "false" in str(bool['aws:SecureTransport']).lower():
                                boolCondition = True
                if 'Principal' in statement:
                    principal = statement['Principal']
                    if "AWS" in principal:
                        aws= principal["AWS"]
                        if "*" in aws:
                            boolPrincipal = True
                    if "*" in principal:
                        boolPrincipal = True
                if 'Action' in statement:
                    if '*' in str(statement['Action']):
                        boolAction = True
    if boolCondition and boolPrincipal and boolAction:
        return CheckResult.PASSED
    else:
        return CheckResult.FAILED    
