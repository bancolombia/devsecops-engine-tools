from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class EC2SecurityGroupsPorts(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EC2 has segurity group ports"
        id = "CKV_AWS_397"
        supported_resources = ['AWS::EC2::SecurityGroup']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                            supported_resources=supported_resources)
        
    def scan_resource_conf(self, conf):
        checks_passed = 0

        if 'Properties' in conf.keys():
            if 'SecurityGroupIngress' in conf['Properties'].keys():
                if isinstance(conf['Properties']['SecurityGroupIngress'], list):
                    for item in conf['Properties']['SecurityGroupIngress']:
                        if 'IpProtocol' in item.keys():
                            if item['IpProtocol'] != '-1':
                                if ('FromPort' in item.keys() and 'ToPort' in item.keys()) :
                                    if item['FromPort'] != "" and item['ToPort'] != "":
                                        if item == conf['Properties']['SecurityGroupIngress'][-1]:
                                            checks_passed += 1
                        elif 'Fn::If' in item.keys():
                            rules= item['Fn::If']
                            for rule in rules :
                                  if isinstance(rule, dict) and 'IpProtocol' in rule:
                                        if rule['IpProtocol'] != '-1':
                                            if ('FromPort' in rule.keys() and 'ToPort' in rule.keys()) :
                                                if rule['FromPort'] != "" and rule['ToPort'] != "":
                                                    if item == conf['Properties']['SecurityGroupIngress'][-1]:
                                                        checks_passed += 1
                            
                                                       

        if checks_passed == 1:
            return CheckResult.PASSED              
        return CheckResult.FAILED

check = EC2SecurityGroupsPorts()