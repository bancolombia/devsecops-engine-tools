from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re


class DocumentDBTagBackUp(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DocumentDB resource has backup tag"
        id = "CKV_AWS_414"
        supported_resources = ['AWS::DocDB::DBCluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        try:
            for tags in conf['Properties']['Tags']:
                if 'Key' in tags.keys() and 'Value' in tags.keys():
                        if tags['Key'] in ["bancolombia:bkmensual", "bancolombia:bkdiario"]:
                            if tags['Value'] in ["documentdb","none"]:
                                return CheckResult.PASSED
                            elif tags['Value']['Fn::If'][1] == "documentdb":
                                return CheckResult.PASSED
                        elif re.search(r'(?i)^bancolombia:planbackup',str(tags['Value'])):
                            return CheckResult.PASSED
            return CheckResult.FAILED
        except Exception:
            return CheckResult.FAILED
            
check = DocumentDBTagBackUp()
