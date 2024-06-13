from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
import re


class VPCEndpointsMultiAZ(BaseResourceCheck):
    def __init__(self):
        name = "Ensures that the Multi AZ for VPC EndPoint service"
        id = "CKV_AWS_416"
        supported_resources = ['AWS::EC2::VPCEndpoint']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        try:
            if conf['Properties']['VpcEndpointType'] == 'Interface':
                if 'Properties' in conf.keys():
                    if 'SubnetIds' in conf['Properties'].keys():
                        try:
                            if isinstance(conf['Properties']['SubnetIds'],list):
                                if len(conf['Properties']['SubnetIds']) >= 2:
                                    return CheckResult.PASSED
                            elif (re.search(r'.*Fn::If.*',str(conf['Properties']['SubnetIds']))):
                                return CheckResult.PASSED
                            elif (re.search(r'.*Fn::Split.*',str(conf['Properties']['SubnetIds']))):
                                return CheckResult.PASSED
                            elif (re.search(r'.*Fn::FindInMap.*',str(conf['Properties']['SubnetIds']))):
                                return CheckResult.PASSED
                            else:
                                return CheckResult.FAILED
                        except Exception as e:
                            return CheckResult.FAILED
                return CheckResult.FAILED
            else:
                return CheckResult.PASSED
        except Exception as e:
            return CheckResult.PASSED

check = VPCEndpointsMultiAZ()