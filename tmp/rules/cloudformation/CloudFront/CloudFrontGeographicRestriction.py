from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class CloudFrontGeographicRestriction(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront has a proper geo-restriction enabled"
        id = "CKV_AWS_401"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        locations = [ "AF", "AL", "AS", "AZ", "BA", "BF", "BW", "BY", "CC", "CD", "CI", "CK", "CU",
        "CX", "CZ", "DJ", "FJ", "FO", "GA", "IO", "IQ", "IR", "JE", "KG", "KI", "KM",
        "KN", "KP", "KZ", "LA", "LI", "LK", "LR", "LS", "LT", "LV", "LY", "MH", "MK",
        "MM", "NF", "PK", "PN", "PS", "PW", "SB", "SC", "SD", "SI", "SK", "ST", "SY",
        "TD", "TG", "TJ", "TK", "TM", "TO", "TL", "TV", "UZ", "VU", "YT", "ZW"]

        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'Restrictions' in conf['Properties']['DistributionConfig'].keys():
                    if 'GeoRestriction' in conf['Properties']['DistributionConfig']['Restrictions'].keys():
                        if 'RestrictionType' in conf['Properties']['DistributionConfig']['Restrictions']['GeoRestriction'].keys():
                            if 'Locations' in conf['Properties']['DistributionConfig']['Restrictions']['GeoRestriction'].keys() and conf['Properties']['DistributionConfig']['Restrictions']['GeoRestriction']['RestrictionType'] == 'blacklist':
                                if isinstance(conf['Properties']['DistributionConfig']['Restrictions']['GeoRestriction']['Locations'], list):
                                    for location in locations:
                                        if location not in conf['Properties']['DistributionConfig']['Restrictions']['GeoRestriction']['Locations']:
                                            return CheckResult.FAILED
                                
                                    return CheckResult.PASSED

        return CheckResult.FAILED    

check = CloudFrontGeographicRestriction()