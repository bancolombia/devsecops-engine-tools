from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class DynamoBaseLineBackupTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Dynamo has base line backup tag"
        id = "CKV_AWS_207"
        supported_resources = ['AWS::DynamoDB::Table']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        contbkf = 0
        contbk = 0
        contbkm = 0
        contbkd = 0
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] == "bancolombia:bkmensual":
                                contbkm = contbkm + 1
                                if ("dynamodb" in str(item['Value']) or "no" in str(item['Value'])): 
                                    contbk = contbk + 1
                            elif item['Key'] == "bancolombia:bkdiario":
                                contbkd = contbkd + 1
                                if ("dynamodb" in str(item['Value']) or "no" in str(item['Value'])): 
                                    contbk = contbk + 1
                contbkf = contbkm + contbkm
                if contbkf == contbk and contbkf == 2:
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
        return CheckResult.FAILED

check = DynamoBaseLineBackupTag()