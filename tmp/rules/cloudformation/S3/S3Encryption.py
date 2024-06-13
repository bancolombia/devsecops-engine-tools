from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


def is_not_empty(a):
    return len(a) > 0


class S3Encryption(BaseResourceCheck):

    def __init__(self):
        name = "Ensure the S3 bucket has server-side-encryption enabled"
        id = "CKV_AWS_320"
        supported_resources = ['AWS::S3::Bucket']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'BucketEncryption' in conf['Properties'].keys():
                if 'ServerSideEncryptionConfiguration' in conf['Properties']['BucketEncryption'].keys():
                    if 'ServerSideEncryptionByDefault' in conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][0].keys():
                        if 'SSEAlgorithm' in conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault'].keys():
                            sseAlgorithm = conf['Properties']['BucketEncryption'][
                                'ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault']['SSEAlgorithm']
                            if 'aws:kms' in str(sseAlgorithm):
                                if 'KMSMasterKeyID' in conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][0]['ServerSideEncryptionByDefault'].keys():
                                    kmskeyid = conf['Properties']['BucketEncryption']['ServerSideEncryptionConfiguration'][
                                        0]['ServerSideEncryptionByDefault']['KMSMasterKeyID']
                                    if kmskeyid is not None and is_not_empty(kmskeyid):
                                        return CheckResult.PASSED
                            elif 'AES256' in str(sseAlgorithm):
                                return CheckResult.PASSED

        return CheckResult.FAILED


check = S3Encryption()
