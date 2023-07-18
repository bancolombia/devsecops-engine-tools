class PipelineConfig:
    def __init__(
        self,
        pipeline_name: str = None,
        default_working_directory: str = None,
        staging_directory: str = None,
    ):
        self.pipeline_name = pipeline_name
        self.default_working_directory = default_working_directory
        self.staging_directory = staging_directory
