from typing import List
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re

class LambdaRuntimeBanistmo(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Lambda has good runtime"
        id = "CKV_AWS_419"
        supported_resources = ['AWS::Lambda::Function']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        regular_expressions = {
            'Java': r'^java(21|17|11|8.al2)$',
            'Python': r'^python3\.([8-9]|1[0-2])$',
            'NodeJS': r'^nodejs(?:1[6|8]|20)\.x$',
        }

        if 'Properties' in conf.keys():
            if 'PackageType' in conf['Properties'].keys():
                 if 'Image' in conf['Properties']['PackageType']:
                      return CheckResult.PASSED
            elif 'Runtime' in conf['Properties'].keys():
                runtime_value = conf['Properties']['Runtime']
                for pattern in regular_expressions.values():
                    if re.search(pattern, runtime_value):
                        return CheckResult.PASSED
            return CheckResult.FAILED
        return CheckResult.FAILED

check = LambdaRuntimeBanistmo()