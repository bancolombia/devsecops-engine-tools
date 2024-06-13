from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSMultiAZEnabled(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances have Multi-AZ enabled"
        id = "CKV_AWS_257"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'DBSnapshotIdentifier' in conf['Properties'].keys():
                if 'Fn::If' in conf['Properties']['DBSnapshotIdentifier']:
                    blockFnIf = conf['Properties']['DBSnapshotIdentifier']['Fn::If']
                    position = 1
                    if 'empty' in blockFnIf[0]:
                        position = 2
                    if 'arn:aws:rds' in blockFnIf[position]:
                        return CheckResult.UNKNOWN
                else:
                    return CheckResult.UNKNOWN
            if 'DBClusterIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            if 'Condition' in conf['Properties'] and 'datical' in str(conf['Properties']['Condition']).lower():
                return CheckResult.UNKNOWN
            if 'MultiAZ' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['MultiAZ']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSMultiAZEnabled()
