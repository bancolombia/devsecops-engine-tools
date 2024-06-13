from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


def is_empty(a):
    return len(a) == 0


class ELBSecureListener(BaseResourceCheck):

    def __init__(self):
        name = "Ensure ELB has Secure Listener"
        id = "CKV_AWS_301"
        supported_resources = ['AWS::ElasticLoadBalancingV2::Listener']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Protocol' in conf['Properties'].keys():
                if conf['Properties']['Protocol'] in ('HTTPS', 'TLS'):
                    if 'Certificates' in conf['Properties'].keys():
                        if isinstance(conf['Properties']['Certificates'], list):
                            for item in conf['Properties']['Certificates']:
                                if 'CertificateArn' in item.keys():
                                    if is_empty(item['CertificateArn']):
                                        return CheckResult.FAILED
                                else:
                                    return CheckResult.FAILED
                    else:
                        return CheckResult.FAILED

        return CheckResult.PASSED


check = ELBSecureListener()
