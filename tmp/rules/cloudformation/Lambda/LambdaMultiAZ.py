from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
import re


class LambdaMultiAZ(BaseResourceCheck):
    def __init__(self):
        name = "Ensures that the lambdas configured on the VPC have at least two Availability Zones associated with them"
        id = "CKV_AWS_417"
        supported_resources = ['AWS::Lambda::Function']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'VpcConfig' in conf['Properties'].keys(): 
                if 'SubnetIds' in conf['Properties']['VpcConfig'].keys(): 
                    try:
                        if isinstance(conf['Properties']['VpcConfig']['SubnetIds'],list):
                            if len(conf['Properties']['VpcConfig']['SubnetIds']) >= 2:
                                return CheckResult.PASSED
                        elif (re.search(r'.*Fn::If.*',str(conf['Properties']['VpcConfig']['SubnetIds']))):
                            return CheckResult.PASSED
                        elif (re.search(r'.*Fn::Split.*',str(conf['Properties']['VpcConfig']['SubnetIds']))):
                            return CheckResult.PASSED
                        elif (re.search(r'.*Fn::FindInMap.*',str(conf['Properties']['VpcConfig']['SubnetIds']))):    
                            return CheckResult.PASSED
                    except Exception as e:
                        return CheckResult.FAILED
        return CheckResult.FAILED

check = LambdaMultiAZ()