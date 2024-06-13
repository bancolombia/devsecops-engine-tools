from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import verified_tag
class EFSConfidentialityTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS has confidentiality tag"
        id = "CKV_AWS_200"
        supported_resources = ['AWS::EFS::FileSystem']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemTags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['FileSystemTags'], list):
                    for item in conf['Properties']['FileSystemTags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] in verified_tag("clasificacion-confidencialidad") and item['Value'] in ["publica","interna","confidencial","restringida"]:
                                return CheckResult.PASSED
        return CheckResult.FAILED

check = EFSConfidentialityTag()