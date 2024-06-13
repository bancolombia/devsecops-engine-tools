from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class EMRApprovedVersion(BaseResourceCheck):
    def __init__(self):
        name = "AWS EMR has ApprovedVersion"
        id = "CKV_AWS_346"
        supported_resources = ['AWS::EMR::Cluster'] 
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'ReleaseLabel' in conf['Properties'].keys():
                if validate_version(conf['Properties']['ReleaseLabel']):
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
                
                

def validate_version(conf):
    #Version bank approved 5.10.0
    try:
        if int(conf.split("-")[1].split(".")[0]) > 5:
            return True
        else:
            return int(conf.split("-")[1].split(".")[0]) >= 5 and int(conf.split("-")[1].split(".")[1]) >= 10 and int(conf.split("-")[1].split(".")[2]) >= 0   
    except:
        return False


check = EMRApprovedVersion()
