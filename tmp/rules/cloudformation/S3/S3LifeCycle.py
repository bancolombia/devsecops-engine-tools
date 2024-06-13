from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class S3LifeCycle(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that at least one lifecycle policy is configured with object expiration and version expiration"
        id = "CKV_AWS_399"
        supported_resources = ['AWS::S3::Bucket']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        values_allowed = ['archiving','kinesis','sterling','transfer']
        try:
            if 'Properties' in conf.keys():
                if 'BucketName' in conf['Properties'].keys():
                    for value in values_allowed:
                        if value in str(conf['Properties']['BucketName']):
                            return CheckResult.PASSED
                    
            if 'Properties' in conf.keys():
                if 'BucketEncryption' in conf['Properties'].keys():
                    if 'ServerSideEncryptionConfiguration' in conf['Properties']['BucketEncryption'].keys():
                        if 'ServerSideEncryptionByDefault' in conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][0].keys():
                            if 'SSEAlgorithm' in conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault'].keys():
                                sseAlgorithm = conf['Properties']['BucketEncryption'][
                                    'ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault']['SSEAlgorithm']
                                if 'AES256' in str(sseAlgorithm):
                                    return CheckResult.PASSED     
            
            if 'Properties' in conf.keys():            
                if 'LifecycleConfiguration' in conf['Properties'].keys():
                    if 'Rules' in conf['Properties']['LifecycleConfiguration'].keys():
                        if len(conf['Properties']['LifecycleConfiguration']['Rules']) > 0:
                            ExpirationInDays=0
                            NoncurrentVersionExpiration=0
                            for RulesCount in conf['Properties']['LifecycleConfiguration']['Rules']:
                                if 'ExpirationInDays' in RulesCount.keys():
                                    ExpirationInDays += 1
                                if 'NoncurrentVersionExpiration' in RulesCount.keys():
                                    NoncurrentVersionExpiration += 1
                            if ExpirationInDays != 0 and NoncurrentVersionExpiration != 0:
                                return CheckResult.PASSED
        except Exception:
            return CheckResult.FAILED

        return CheckResult.FAILED
check = S3LifeCycle()