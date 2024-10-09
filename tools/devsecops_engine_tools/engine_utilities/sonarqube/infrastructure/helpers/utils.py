import re

def set_repository(pipeline_name, source_code_management):
    if re.search('_MR_', pipeline_name) is None:
        return source_code_management
    else:
        splittedPipeline = pipeline_name.split('_MR_')
        return source_code_management + '?path=/' + splittedPipeline[1]

def set_environment(branch):
    if branch in ["trunk", "master"]:
        return "Production"
    else:
        return "Development"

def invalid_branch(branch):
    if branch in ["trunk", "master", "develop"]:
        return False
    else:
        return True

def invalid_pipeline(pipeline_name):
    regex = re.compile(r'_test|Deprecated_|JUBILADO_|Borrar|eliminar|No_usar', re.IGNORECASE)
    if regex.search(pipeline_name) is None:
        return False
    else:
        return True