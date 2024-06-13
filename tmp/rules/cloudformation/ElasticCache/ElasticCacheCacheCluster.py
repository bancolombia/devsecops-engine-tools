from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class ElasticCacheCacheCluster(BaseResourceCheck):
    def __init__(self):
        name = "Ensure PreferredAvailabilityZones are defined and AZMode is set to cross-az"
        id = "CKV_AWS_362"
        supported_resources = ['AWS::ElastiCache::CacheCluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Engine' in conf['Properties'].keys():
                if "memcache" in str(conf['Properties']['Engine']).lower():
                    if "AZMode" in conf['Properties'].keys() and "PreferredAvailabilityZones" in conf['Properties'].keys():
                        if "cross-az" in str(conf['Properties']['AZMode']).lower() and str(conf['Properties']['PreferredAvailabilityZones']).lower():
                            return CheckResult.PASSED
                        else:
                            return CheckResult.FAILED
                    return CheckResult.FAILED
                elif  "redis" in str(conf['Properties']['Engine']).lower():
                    return CheckResult.SKIPPED
        return CheckResult.FAILED


check = ElasticCacheCacheCluster()