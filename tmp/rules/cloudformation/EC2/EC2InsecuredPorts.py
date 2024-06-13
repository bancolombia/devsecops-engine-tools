from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class EC2InsecuredPorts(BaseResourceCheck):
    def __init__(self):
        name = "Ensure security groups no allow ingress to ports 20,21,23,25"
        id = "CKV_AWS_334"
        supported_resources = ['AWS::EC2::SecurityGroup','AWS::EC2::SecurityGroupIngress','AWS::EC2::SecurityGroupEgress']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        rulesSGI = []
        rulesSGE = []
        if conf['Type'] == 'AWS::EC2::SecurityGroup':
            if 'Properties' in conf.keys():
                if 'SecurityGroupIngress' in conf['Properties'].keys():
                    rulesSGI = conf['Properties']['SecurityGroupIngress']
                if 'SecurityGroupEgress' in conf['Properties'].keys():
                    rulesSGE = conf['Properties']['SecurityGroupEgress']
        elif conf['Type'] == 'AWS::EC2::SecurityGroupIngress':
            if 'Properties' in conf.keys():
                rulesSGI = []
                rulesSGI.append(conf['Properties'])
        elif conf['Type'] == 'AWS::EC2::SecurityGroupEgress':
            if 'Properties' in conf.keys():
                rulesSGE = []
                rulesSGE.append(conf['Properties'])

        for rule in rulesSGI:
            if rule.__contains__('FromPort') and rule.__contains__('ToPort'):
                if isinstance(rule['FromPort'], int) and isinstance(rule['ToPort'], int):
                    if int(rule['FromPort']) in [20, 21, 23, 25] or int(rule['ToPort']) in [20, 21, 23, 25]:
                        return CheckResult.FAILED
        for rule in rulesSGE:
            if rule.__contains__('FromPort') and rule.__contains__('ToPort'):
                if isinstance(rule['FromPort'], int) and isinstance(rule['ToPort'], int):
                    if int(rule['FromPort']) in [20, 21, 23, 25] or int(rule['ToPort']) in [20, 21, 23, 25]:
                        return CheckResult.FAILED
        return CheckResult.PASSED

check = EC2InsecuredPorts()
