from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSSubnetGroup(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has an subnet group Associate"
        id = "CKV_AWS_302"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'SourceDBInstanceIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'DBSubnetGroupName' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED

check = RDSSubnetGroup()
