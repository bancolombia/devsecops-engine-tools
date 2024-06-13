from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re

class S3BucketPolicy(BaseResourceCheck):
    def __init__(self):
        name = "Ensure buckets dont have a blocking policy document with deny all principals"
        id = "CKV_AWS_406"
        supported_resources = ['AWS::S3::BucketPolicy']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        try:
            for statement in conf['Properties']['PolicyDocument']['Statement']:
                try:
                    if ('s3:*' in statement['Action']) and ('Deny' in statement['Effect']) and ('*' in statement['Principal']):
                        
                        if 'Resource' in statement.keys():
                            try:
                                if 'Condition' in statement.keys():
                                    if 'Bool' in statement['Condition'].keys():
                                        if 'aws:SecureTransport' in statement['Condition']['Bool'].keys():
                                            return CheckResult.PASSED
                                    elif 'StringNotEquals' in statement['Condition'].keys():
                                        if isinstance(statement['Condition']['StringNotEquals']['aws:PrincipalArn'],list):
                                            for principal in statement['Condition']['StringNotEquals']['aws:PrincipalArn']:
                                                if re.search(r'.*deployment-Rol-VSTS.*',principal):
                                                    return CheckResult.PASSED
                                                elif re.search(r'.*cloudformation-service-deployment-role-vsts.*',principal):
                                                    return CheckResult.PASSED
                                        else:
                                            if re.search(r'.*deployment-Rol-VSTS.*',statement['Condition']['StringNotEquals']['aws:PrincipalArn']):
                                                return CheckResult.PASSED
                                            elif re.search(r'.*cloudformation-service-deployment-role-vsts.*',statement['Condition']['StringNotEquals']['aws:PrincipalArn']):
                                                return CheckResult.PASSED
                                    elif 'NotIpAddress' in statement['Condition'].keys():
                                        if statement['Condition']['NotIpAddress']['aws:SourceIp'] is not None:
                                            return CheckResult.PASSED
                                    else:
                                        return CheckResult.FAILED 
                                else:
                                    return CheckResult.FAILED
                            except Exception:
                                return CheckResult.FAILED
                        else:
                            return CheckResult.FAILED   
                    else:
                        return CheckResult.PASSED    
                except Exception:
                    return CheckResult.PASSED 
            
        except Exception:
            return CheckResult.FAILED
check = S3BucketPolicy()