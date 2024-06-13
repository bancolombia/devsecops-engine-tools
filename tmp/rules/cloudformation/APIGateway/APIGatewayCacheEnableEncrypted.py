from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class APIGatewayCacheEnableEncrypted(BaseResourceCheck):
    
    def __init__(self):
        name = "Ensure API Gateway encrypted if caching is enabled"
        id = "CKV_AWS_263"
        supported_resources = ['AWS::ApiGateway::Stage','AWS::ApiGateway::Deployment']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)


    def scan_resource_conf(self, conf):

        contStage = 0
        contStageNA = 0
        contDeployNA = 0
        contDeploy = 0
        if conf['Type'] == 'AWS::ApiGateway::Stage':
            if 'Properties' in conf.keys():
                if 'MethodSettings' in conf['Properties'].keys():
                    if isinstance(conf['Properties']['MethodSettings'], list):
                        for item in conf['Properties']['MethodSettings']:
                            if 'CachingEnabled' in item.keys():
                                if item['CachingEnabled'] in ["true",True]:
                                    if 'CacheDataEncrypted' in item.keys(): 
                                        if item['CacheDataEncrypted'] in ["true",True]:
                                            contStage = contStage + 1
                                else:
                                 contStageNA = contStageNA + 1
                            else:    
                                contStageNA = contStageNA + 1     
                    if (len(conf['Properties']['MethodSettings']) - contStageNA) == contStage:
                        return CheckResult.PASSED
                    else:
                        return CheckResult.FAILED
                return CheckResult.PASSED
                                 
        if conf['Type'] == 'AWS::ApiGateway::Deployment':
            if 'Properties' in conf.keys():
                if 'StageDescription' in conf['Properties'].keys():
                    if 'CachingEnabled' in conf['Properties']['StageDescription'].keys():
                        if conf['Properties']['StageDescription']['CachingEnabled'] in ["true",True]:
                            if 'CacheDataEncrypted' in conf['Properties']['StageDescription'].keys():
                                if conf['Properties']['StageDescription']['CacheDataEncrypted']:
                                    return CheckResult.PASSED
                    elif 'MethodSettings' in conf['Properties']['StageDescription'].keys():
                        if isinstance(conf['Properties']['StageDescription']['MethodSettings'], list):
                            for item in conf['Properties']['StageDescription']['MethodSettings']:
                                if 'CachingEnabled' in item.keys():
                                    if item['CachingEnabled'] in ["true",True]:
                                        if 'CacheDataEncrypted' in item.keys(): 
                                            if item['CacheDataEncrypted'] in ["true",True]:
                                                contDeploy = contDeploy + 1
                                    else:
                                        contDeployNA = contDeployNA + 1
                                else:
                                    contDeployNA = contDeployNA + 1
                        if (len(conf['Properties']['StageDescription']['MethodSettings'])-contDeployNA) == contDeploy:
                            return CheckResult.PASSED
                        else:
                            return CheckResult.FAILED
                return CheckResult.PASSED


check = APIGatewayCacheEnableEncrypted()
