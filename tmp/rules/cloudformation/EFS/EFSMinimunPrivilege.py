from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.type_forcers import force_list
import ast
import re


class EFSMinimumPrivilege(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS policies documents dont allow \"*\" as a statement's actions and Resources"
        id = "CKV_AWS_360"
        supported_resources = ['AWS::EFS::FileSystem']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        myproperties = conf.get("Properties")
        if isinstance(myproperties, dict) and 'FileSystemPolicy' in myproperties.keys():
            return check_policy(myproperties['FileSystemPolicy'])
        return CheckResult.UNKNOWN


check = EFSMinimumPrivilege()


def check_policy(policy_block):
    if policy_block:
        if isinstance(policy_block, str):
            policy_block = ast.literal_eval(policy_block)
        if isinstance(policy_block, dict) and 'Statement' in policy_block.keys():
            for statement in force_list(policy_block['Statement']):
                if statement.get('Effect', ['Allow']) == 'Allow':
                    if check_action(statement) or check_resource(statement):
                        return CheckResult.FAILED
                return CheckResult.PASSED
        else:
            return CheckResult.PASSED
    else:
        return CheckResult.PASSED


def check_action(statement):
    return 'Action' in statement and '*' in str(force_list(statement['Action']))


def check_resource(statement):
    if 'Resource' in statement:   
        con = 0
        for x in force_list(statement['Resource']):
            string_val, n = re.subn('({|\'|\\[|\\s|\\]|}|,|-|/|\\$)', '', str(x))
            string_val_final, n = re.subn('__startline__:.[0-9]*__endline__:.[0-9]*', '', str(string_val))
            if bool(re.search("((Fn::Join|Fn::Sub|arn).[a-zA-Z0-9._:]*.(\\*$)|^[a-zA-Z0-9_:]*$)", string_val_final)):
                con = con+1
        if con == len(force_list(statement['Resource'])):
            return False
        if '*' in str(force_list(statement['Resource'])):
            return True
    return False
