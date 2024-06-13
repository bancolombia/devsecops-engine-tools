from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
import ast
import re


class LambdaRoleMinimunPrivilege(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Lambda key policy doesnt contain wildcard (*) in principal"
        id = "CKV_AWS_321"
        supported_resources = ["AWS::IAM::Role"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        myproperties = conf.get("Properties")
        # catch for inline policies
        if (
            isinstance(myproperties, dict)
            and "Policies" in myproperties.keys()
            and isinstance(myproperties, dict)
            and "AssumeRolePolicyDocument" in myproperties.keys()
        ):
            rolepolicy = myproperties["AssumeRolePolicyDocument"]
            policies = myproperties["Policies"]
            if check_rolepolicy(rolepolicy):
                if len(policies) > 0:
                    for policy in policies:
                        if not isinstance(policy, dict):
                            return CheckResult.UNKNOWN
                        if policy.get("PolicyDocument"):
                            result = check_policy(policy["PolicyDocument"])
                            if result == CheckResult.FAILED:
                                return result
                    return CheckResult.PASSED
                # not empty and had non failing policies
                return CheckResult.UNKNOWN
            else:
                return CheckResult.UNKNOWN


def check_policy(policy_block):
    if policy_block:
        if isinstance(policy_block, str):
            policy_block = ast.literal_eval(policy_block)
        if isinstance(policy_block, dict) and "Statement" in policy_block.keys():
            for statement in force_list(policy_block["Statement"]):
                if statement.get("Effect", ["Allow"]) == "Allow":
                    if check_action(statement) or check_resource(statement):
                        return CheckResult.FAILED
                return CheckResult.PASSED
        else:
            return CheckResult.PASSED
    else:
        return CheckResult.PASSED


def check_action(statement):
    return "Action" in statement and "*" in force_list(statement["Action"])


def check_rolepolicy(statements):
    if statements and isinstance(statements, dict) and "Statement" in statements.keys():
        for statement in force_list(statements["Statement"]):
            if "Principal" in statement:
                if "Service" in statement["Principal"]:
                    if "lambda.amazonaws.com" in statement["Principal"]["Service"]:
                        return True


def check_resource(statement):
    if "Resource" in statement:
        if "Action" in statement and any(
            x
            for x in [
                "rekognition:CompareFaces",
                "rekognition:CreateCollection",
                "rekognition:DetectFaces",
                "rekognition:DetectLabels",
                "rekognition:DetectModerationLabels",
                "rekognition:DetectProtectiveEquipment",
                "rekognition:DetectText",
                "rekognition:GetCelebrityInfo",
                "rekognition:GetCelebrityRecognition",
                "rekognition:GetContentModeration",
                "rekognition:GetFaceDetection",
                "rekognition:GetFaceSearch",
                "rekognition:GetLabelDetection",
                "rekognition:GetPersonTracking",
                "rekognition:GetSegmentDetection",
                "rekognition:GetTextDetection",
                "rekognition:RecognizeCelebrities",
                "rekognition:StartCelebrityRecognition",
                "rekognition:StartContentModeration",
                "rekognition:StartFaceDetection",
                "rekognition:StartLabelDetection",
                "rekognition:StartPersonTracking",
                "rekognition:StartSegmentDetection",
                "rekognition:StartTextDetection",
                "logs:PutLogEvents",
                "ec2:DescribeNetworkInterfaces",
            ]
            if x in force_list(statement["Action"])
        ):
            return False
        con = 0
        for x in force_list(statement["Resource"]):
            string_val, n = re.subn("({|'|\\[|\\s|\\]|}|,|-|/|\\$)", "", str(x))
            string_val_final, n = re.subn("__startline__:.[0-9]*__endline__:.[0-9]*", "", str(string_val))
            if bool(re.search("((Fn::Join|Fn::Sub|arn).[a-zA-Z0-9._:]*.(\\*$)|^[a-zA-Z0-9_:]*$)", string_val_final)):
                con = con + 1
        if con == len(force_list(statement["Resource"])):
            return False
        if "*" in str(force_list(statement["Resource"])):
            return True
    return False


check = LambdaRoleMinimunPrivilege()
