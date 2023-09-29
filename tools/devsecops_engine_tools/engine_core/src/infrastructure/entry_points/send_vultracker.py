import os
import argparse
import sys
import json
from devsecops_engine_utilities.defect_dojo import DefectDojo, ImportScanRequest, Connect
#from common_devsecops_lib.devsecops_engine_utilities.defect_dojo import DefectDojo, ImportScanRequest, Connect
def get_inputs_from_cli(args):
	try:
		parser = argparse.ArgumentParser()
		parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
		parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
		parser.add_argument("--tool", type=str, required=True, help="")
		parser.add_argument("--environment", type=str, required=True, help="")
		parser.add_argument("-pt", "--personal_access_token", 
			required=False, help="System access token")
		parser.add_argument("-tc", "--token_cmdb", 
			required=False, help="token Cmdb for list evcs") 
		parser.add_argument("-tv", "--token_vultracker", 
			required=False, help="token vultracker")    

		args = parser.parse_args()
		return (
			args.personal_access_token,
			args.token_cmdb,
			args.token_vultracker,
		)
	except Exception as ex:
		print("Handling run-time error send_vultracker input_arg:")
		print(ex)
		print('"##vso[task.complete result=SucceededWithIssues;]DONE"')
		
def send_vultracker(path_file):
	try:
		(
		    personal_access_token,
            token_cmdb,
            token_vultracker
        ) = (get_inputs_from_cli(sys.argv[1:]))
		enviroment_mapping = {
		'dev': 'Development',
		'qa': 'Staging',
		'pdn': 'Production'
			}
		source_code_management_uri = f'{os.environ.get("SYSTEM_TASKDEFINITIONSURI")}{os.environ.get("BUILD_PROJECTNAME")}/_git/{os.environ.get("BUILD_REPOSITORY_NAME")}'
		source_code_management_uri = source_code_management_uri.replace(" ", "%20")
		branch_name = os.environ.get("BUILD_SOURCEBRANCHNAME")
		if (str(branch_name) == "trunk") or (str(branch_name) == "develop") or (str(branch_name) == "master"):
			request: ImportScanRequest = Connect.cmdb(
			cmdb_mapping={
			"product_type_name": "nombreevc",
			"product_name": "nombreapp",
			"tag_product": "nombreentorno",
			"product_description": "arearesponsableti",
			"codigo_app": "CodigoApp",
			},
			
			compact_remote_config_url=os.environ.get("HOST_REMOTE_CONFIG"),
			personal_access_token= personal_access_token,
			token_cmdb= token_cmdb,
			host_cmdb = os.environ.get("HOST_CMDB"),
			expression=r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_",
			token_defect_dojo= token_vultracker,
			host_defect_dojo = os.environ.get("HOST_VULTRACKER"),
			scan_type="Checkov Scan",
			engagement_name= os.environ.get("BUILD_DEFINITIONNAME"),
			service = os.environ.get("BUILD_DEFINITIONNAME"),
			file=path_file,
			version = os.environ.get("BUILD_BUILDID"),
			build_id= os.environ.get("BUILD_BUILDNUMBER"),
			source_code_management_uri = source_code_management_uri,
			branch_tag = os.environ.get("BUILD_SOURCEBRANCH"),
			commit_hash = os.environ.get("BUILD_SOURCEVERSION"),
			environment = enviroment_mapping[os.environ.get("ENV")],  
			tags = "evc"
			)
			
			response = DefectDojo.send_import_scan(request)
			print("Report sent to vultracker: ",response.test_url)
	except Exception as ex:
		print("Handling run-time error send_vultracker info:")
		print(ex)
		#print('"##vso[task.complete result=SucceededWithIssues;]DONE"')