from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
import ast

class SESNotSMTP(BaseResourceCheck):
    def __init__(self):
        name = "AWS SES has not SMTP by default"
        id = "CKV_AWS_345"
        supported_resources = ['AWS::IAM::Role'] 
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
            myproperties = conf.get("Properties")
            if isinstance(myproperties, dict) and 'Policies' in myproperties.keys():
                policies = myproperties['Policies']
                if len(policies) > 0:
                    for policy in policies:
                        if not isinstance(policy, dict):
                            return CheckResult.UNKNOWN
                        if policy.get('PolicyDocument'):
                            result = check_policy(policy['PolicyDocument'])
                            if result == CheckResult.FAILED:
                                return result
                    return CheckResult.PASSED
                return CheckResult.UNKNOWN

            

def check_policy(policy_block):
    if policy_block:
        if isinstance(policy_block, str):
            policy_block = ast.literal_eval(policy_block)
        if isinstance(policy_block, dict) and 'Statement' in policy_block.keys():
            for statement in force_list(policy_block['Statement']):
                if statement.get('Effect', ['Allow']) == 'Allow':
                    if check_action(statement):
                        return CheckResult.FAILED
                return CheckResult.PASSED
        else:
            return CheckResult.PASSED
    else:
        return CheckResult.PASSED


def check_action(statement):
    return 'Action' in statement and 'ses:SendRawEmail' in force_list(statement['Action'])


check = SESNotSMTP()
