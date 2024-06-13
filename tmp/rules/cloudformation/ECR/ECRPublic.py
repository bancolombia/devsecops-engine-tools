from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class ECRPublic(BaseResourceCheck):
    def __init__(self):
        name = "Ecr public repositories isn't permited"
        id = "CKV_AWS_393"
        supported_resources = ['AWS::ECR::PublicRepository']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            return CheckResult.FAILED

check = ECRPublic()