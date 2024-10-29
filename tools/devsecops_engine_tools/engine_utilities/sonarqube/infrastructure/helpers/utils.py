import re

def set_repository(pipeline_name, source_code_management):
    if re.search('_MR_', pipeline_name) is None:
        return source_code_management
    else:
        splittedPipeline = pipeline_name.split('_MR_')
        return source_code_management + '?path=/' + splittedPipeline[1]
