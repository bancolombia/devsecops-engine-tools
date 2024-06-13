from ast import Str
import json
from typing import Dict
from xmlrpc.client import Boolean
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
import logging


class APIGatewayPrivilegesRolesCICID(BaseResourceCheck):
    def __init__(self):
        name = "Ensure API Gateway has not privileges role CI/CD"
        id = "CKV_AWS_311"
        supported_resources = ['AWS::ApiGateway::RestApi']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)


    def validate_statement(self, statement):
        if 'Effect' in statement:
            if statement['Effect'] == "Deny":
                if 'Principal' in statement:
                    principal = statement['Principal']
                    if "cloudformation-service-deployment-role-vsts" in str(principal):
                        self.boolPrincipal = True
                if 'Action' in statement:
                    if 'execute-api:Invoke' in statement['Action']:
                        self.boolAction = True
                if 'Resource' in statement:
                    if 'execute-api:/*' in str(statement['Resource']):
                        self.boolResource = True
    

    def process_str_json(self, policy):
        try:
            self.boolPrincipal
            for statement in json.loads(policy)['Statement']:
                 self.validate_statement(statement)
        except Exception as e:
            logging.error(f"Malformed policy configuration {str(policy)} of resource {self.entity_path}\n{e}")
            return CheckResult.UNKNOWN
            

    def scan_resource_conf(self, conf):
        self.boolPrincipal = False
        self.boolAction = False
        self.boolResource = False
        if conf.get('Properties'):
            if conf['Properties'].get('Policy'):
                policy = conf['Properties']['Policy']
                if isinstance(policy, str):
                    self.process_str_json(policy)
                elif isinstance(policy,Dict):
                    policy_split = str(policy).split("'")
                    for policy_str in policy_split:
                        if 'Statement' in policy_str and 'Version' in policy_str:
                           self.process_str_json(policy_str)                      
        if self.boolPrincipal and self.boolAction and self.boolResource:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


check = APIGatewayPrivilegesRolesCICID()
 