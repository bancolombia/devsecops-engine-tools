from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class KMSKeyLimit(BaseResourceCheck):
    def __init__(self):
        name = "Ensure KMS has key restriction"
        id = "CKV_AWS_402"
        supported_resources = ['AWS::KMS::Key']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self,conf):
        
        required_actions = [
            "kms:Describe*",
            "kms:PutKeyPolicy",
            "kms:Create*",
            "kms:Update*",
            "kms:EnableKey*",
            "kms:RevokeGrant",
            "kms:List*",
            "kms:DisableKey*",
            "kms:Get*",
            "kms:Delete*",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:RetireGrant"
        ]
        
        if 'Properties' in conf and 'KeyPolicy' in conf['Properties']:
            key_policy = conf['Properties']['KeyPolicy']
            if 'Statement' in key_policy:
                for statement in key_policy['Statement']:
                    try:
                        if statement.get('Effect') == "Allow":
                            principal = statement.get('Principal', {})
                            actions = statement.get('Action', [])
                            if isinstance(principal, dict) and 'AWS' in principal:
                                if all(action in actions for action in required_actions):
                                            return CheckResult.PASSED
                    except:
                        return CheckResult.UNKNOWN
                return CheckResult.FAILED


check = KMSKeyLimit()
