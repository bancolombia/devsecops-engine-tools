from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re

class RDSParamsGroup(BaseResourceCheck):

    def __init__(self):
        name = "Ensure well defined parameters group and options groups "
        id = "CKV_AWS_403"
        supported_resources = ['AWS::RDS::DBParameterGroup','AWS::RDS::DBClusterParameterGroup','AWS::RDS::OptionGroup']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        count = 0
        if conf['Type'] == 'AWS::RDS::DBParameterGroup' or conf['Type'] == 'AWS::RDS::DBClusterParameterGroup':
            if 'Properties' in conf.keys():
                if 'Family' in conf['Properties'].keys():
                    if re.search(r'.*(mysql5\.7|mysql8\.0)$',conf['Properties']['Family']):
                        try:
                            if (conf['Properties']['Parameters']['local_infile'] == 0) and (
                                conf['Properties']['Parameters']['sql_mode'] == 'NO_ENGINE_SUBSTITUTION') and (
                                conf['Properties']['Parameters']['log_error_verbosity'] == 2):
                                return CheckResult.PASSED
                        except Exception:
                            return CheckResult.FAILED
                    elif re.search(r'.*(postgres(ql)?13|postgres(ql)?14)$',conf['Properties']['Family']):
                        try:
                            if (conf['Properties']['Parameters']['log_statement'] == 'ddl') and (
                                conf['Properties']['Parameters']['log_min_messages'] == 'warning') and (
                                conf['Properties']['Parameters']['debug_print_parse'] == 0) and (
                                conf['Properties']['Parameters']['debug_print_parse'] == 0    
                                ) and (conf['Properties']['Parameters']['debug_print_rewritten'] == 0
                                ) and (conf['Properties']['Parameters']['debug_print_plan'] == 0) and (conf['Properties']['Parameters']['debug_pretty_print'] == 1)and (conf['Properties']['Parameters']['log_connections'] == 1) and (conf['Properties']['Parameters']['log_disconnections'] == 1) and (conf['Properties']['Parameters']['log_destination'] == 'stderr') and (conf['Properties']['Parameters']['log_rotation_age'] == 60) and (conf['Properties']['Parameters']['log_rotation_size'] == 102400) and (conf['Properties']['Parameters']['log_min_error_statement'] == 'error') and (conf['Properties']['Parameters']['log_error_verbosity'] == 'default') and (conf['Properties']['Parameters']['log_hostname'] == 0) and (conf['Properties']['Parameters']['pgaudit.role'] == 'rds_pgaudit') and ('pgaudit.log' in conf['Properties']['Parameters'].keys()) and (conf['Properties']['Parameters']['logical_decoding_work_mem'] == 64):
                                    if 'aurora' in conf['Properties']['Family'] and (
                                        conf['Properties']['Parameters']['shared_preload_libraries'] == 'pgaudit, pg_stat_statements'):
                                        return CheckResult.PASSED
                                    elif conf['Properties']['Parameters']['timezone'
                                        ] == 'America/Bogota'and (conf['Properties']['Parameters']['shared_preload_libraries'] == 'pgaudit, pg_stat_statements, pg_cron'):
                                        return CheckResult.PASSED
                        except Exception:
                            return CheckResult.FAILED
                    elif 'oracle-ee-19' in conf['Properties']['Family']:
                        try:
                            if (conf['Properties']['Parameters']['audit_trail'] == 'XML,EXTENDED')and ('false' in str(conf['Properties']['Parameters']['_trace_files_public']).lower()):
                                return CheckResult.PASSED
                        except Exception:
                            return CheckResult.FAILED
                        
                    elif 'sqlserver-ee-15.0' in conf['Properties']['Family']:
                        try:
                            if (conf['Properties']['Parameters']['remote access'] == 0) and (conf['Properties']['Parameters']['optimize for ad hoc workloads'] == 1) and (conf['Properties']['Parameters']['cost threshold for parallelism'] == 50):
                                return CheckResult.PASSED
                        except Exception:
                            return CheckResult.FAILED
                    else:
                        return CheckResult.PASSED
            return CheckResult.FAILED
        elif conf['Type'] == 'AWS::RDS::OptionGroup':
            if 'Properties' in conf.keys():
                if 'EngineName' in conf['Properties'].keys() and 'MajorEngineVersion' in conf['Properties'].keys():
                    if conf['Properties']['EngineName'] == 'mysql' and (
                        conf['Properties']['MajorEngineVersion'] == '5.7' or 
                        conf['Properties']['MajorEngineVersion'] == '8.0'):
                        try:
                            for item in conf['Properties']['OptionConfigurations']:
                                if item['OptionName'] == 'MARIADB_AUDIT_PLUGIN':
                                    for settings in item['OptionSettings']:
                                        if 'Name' in settings.keys() and 'Value' in settings.keys():
                                            if settings['Name'] == "SERVER_AUDIT_EVENTS" and "CONNECT,QUERY" in str(settings['Value']):
                                                count+=1
                                            elif settings['Name'] == "SERVER_AUDIT_FILE_ROTATE_SIZE" and "100000000" in str(settings['Value']):
                                                count+=1
                                            elif settings['Name'] == "SERVER_AUDIT_FILE_ROTATIONS" and "100" in str(settings['Value']):
                                                count+=1
                                    if count == 3:
                                        return CheckResult.PASSED
                                    
                            return CheckResult.FAILED
                        except Exception:
                            return CheckResult.FAILED
                    else:
                        return CheckResult.PASSED   
            return CheckResult.FAILED          

check = RDSParamsGroup()