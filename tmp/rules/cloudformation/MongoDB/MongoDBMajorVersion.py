from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
import re 

class MongoDBMajorVersion(BaseResourceCheck):

    def __init__(self):
        name = "Ensure MongoDB has major version"
        id = "CKV_AWS_385"
        supported_resources = ['MongoDB::Atlas::Cluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        pattern = r'^(6\.[01]\d*|6\.0|7(\.[01])?|8\.0)$'
        if 'Properties' in conf.keys():
            if 'MongoDBMajorVersion' in conf['Properties'].keys() and re.match(pattern, str(conf['Properties']['MongoDBMajorVersion'])):
                return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = MongoDBMajorVersion()
