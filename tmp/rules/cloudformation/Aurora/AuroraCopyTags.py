from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class AuroraCopyTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Aurora instance has copy tags to snapshots enabled"
        id = "CKV_AWS_287"
        supported_resources = ['AWS::RDS::DBCluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'SnapshotIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'CopyTagsToSnapshot' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['CopyTagsToSnapshot']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = AuroraCopyTags()