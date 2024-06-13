from typing import List
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import verified_tag

class LambdaExecutionVPC(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Lambda has configured for execution into VPC"
        id = "CKV_AWS_317"
        supported_resources = ['AWS::Lambda::Function']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Code' in conf['Properties'].keys():
                if 'ZipFile' in conf['Properties']['Code']:
                    if 'headers' in str(conf['Properties']['Code']['ZipFile']):
                        return CheckResult.UNKNOWN
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] in verified_tag("clasificacion-confidencialidad") and item['Value'] in ["na","publica","interna"]:
                                return CheckResult.UNKNOWN
            if 'VpcConfig' in conf['Properties'].keys():
                if 'SecurityGroupIds' in conf['Properties']['VpcConfig'].keys() and 'SubnetIds' in conf['Properties']['VpcConfig'].keys():
                    return CheckResult.PASSED
        return CheckResult.FAILED

check = LambdaExecutionVPC()