from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

def is_not_empty(a):
    return len(a) > 0

class ElasticCacheTransitEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the Elasticache Replication Group is securely encrypted at transit"
        id = "CKV_AWS_323"
        supported_resources = ['AWS::ElastiCache::ReplicationGroup']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'TransitEncryptionEnabled' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['TransitEncryptionEnabled']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = ElasticCacheTransitEncryption()