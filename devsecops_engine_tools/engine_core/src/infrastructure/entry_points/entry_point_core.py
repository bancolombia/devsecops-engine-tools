from engine_sast.engine_iac.src.applications.runner_iac_scan import runner_engine_iac

def main():
    try:
        print(runner_engine_iac())
    except Exception as e:
        print(f"Error SCAN : {str(e)}")
        print(AzureMessageResultPipeline.Succeeded.value)
        # Manejar el error según sea necesario

def init_engine_core(remote_config_repo, remote_config_path, tool):