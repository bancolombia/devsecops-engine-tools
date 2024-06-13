
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import CYBEARK_TENABLE_SEGMENTS

class VPCSecurityGroupPortSpecific(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC Security Group Ports are specific"
        id = "CKV_AWS_312"
        supported_resources = ['AWS::EC2::SecurityGroup']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        rules = []
        if 'Properties' in conf.keys():
            if 'VpcId' in conf['Properties'].keys():
                if 'SecurityGroupIngress' in conf['Properties'].keys():
                    rules = conf['Properties']['SecurityGroupIngress']
                    for rule in rules:
                        if rule.__contains__('IpProtocol'):
                            if isinstance(rule['IpProtocol'], int):
                                if int(rule['IpProtocol']) == int(-1):
                                    if 'CidrIp' in rule.keys() and rule['CidrIp'] not in CYBEARK_TENABLE_SEGMENTS:
                                        return CheckResult.FAILED
        return CheckResult.PASSED


check = VPCSecurityGroupPortSpecific()
