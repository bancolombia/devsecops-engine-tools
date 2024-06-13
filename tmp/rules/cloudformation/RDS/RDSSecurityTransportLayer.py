from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSSecurityTransportLayer(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has security transport layer"
        id = "CKV_AWS_295"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Engine' in conf['Properties'].keys() and 'oracle' in str(conf['Properties']['Engine']).lower():
                return CheckResult.UNKNOWN
            if any(x for x in ['DBClusterIdentifier','DBSnapshotIdentifier'] if x in conf['Properties'].keys()):
                return CheckResult.UNKNOWN
            if 'CACertificateIdentifier' in conf['Properties'].keys():
                if conf['Properties']['CACertificateIdentifier'] == "rds-ca-rsa2048-g1":
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSSecurityTransportLayer()