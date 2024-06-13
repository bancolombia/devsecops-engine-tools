from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re

class MQBrokerMultiAZ(BaseResourceCheck):

    def __init__(self):
        name = "Ensures that the Multi AZ for MQ in Production"
        id = "CKV_AWS_415"
        supported_resources = ['AWS::AmazonMQ::Broker']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if conf['Type'] == 'AWS::AmazonMQ::Broker':
            if 'Properties' in conf.keys():
                if 'DeploymentMode' in conf['Properties'].keys():
                    try:
                        if (conf['Properties']['DeploymentMode'] in ['ACTIVE_STANDBY_MULTI_AZ', 'CLUSTER_MULTI_AZ']):
                            return CheckResult.PASSED
                        elif conf['Properties']['DeploymentMode'].get('Fn::If',["",""])[1] in ['ACTIVE_STANDBY_MULTI_AZ', 'CLUSTER_MULTI_AZ']:
                            return CheckResult.PASSED
                        elif conf['Properties']['DeploymentMode']['Fn::FindInMap'][0] == 'mrabbitmq':
                            return CheckResult.PASSED
                        else:
                            return CheckResult.FAILED
                    except Exception as e:
                        return CheckResult.FAILED
                return CheckResult.PASSED
            return CheckResult.PASSED
        
check = MQBrokerMultiAZ()