from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class VPCEndpoints(BaseResourceCheck):
    def __init__(self):
        name = "VPC Endpoints isn't permited"
        id = "CKV_AWS_373"
        supported_resources = [ 'AWS::EC2::VPCEndpoint','AWS::EC2::VPC','AWS::EC2::Subnet','AWS::EC2::VPCAttachment', 'AWS::EC2::TransitGateway', 'AWS::EC2::TransitGatewayPeeringAttachment', 'AWS::EC2::InternetGateway', 'AWS::EC2::VPCGatewayAttachment', 'AWS::EC2::EgressOnlyInternetGateway', 'AWS::EC2::CarrierGateway', 'AWS::EC2::Route', 'AWS::EC2::SubnetRouteTableAssociation' ]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            return CheckResult.FAILED

check = VPCEndpoints()