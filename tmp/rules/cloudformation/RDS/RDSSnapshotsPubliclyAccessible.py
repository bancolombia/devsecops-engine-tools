from typing import Any, List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class RDSSnapshotsPubliclyAccessible(BaseResourceValueCheck):

    def __init__(self):
        name = "AWS RDS snapshots are accessible to public"
        id = "CKV_AWS_252"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources,
                         missing_block_result=CheckResult.PASSED)

    def get_inspected_key(self):
        return 'Properties/PubliclyAccessible'

    def get_expected_values(self) -> List[Any]:
        return [False,"false"]        


check = RDSSnapshotsPubliclyAccessible()