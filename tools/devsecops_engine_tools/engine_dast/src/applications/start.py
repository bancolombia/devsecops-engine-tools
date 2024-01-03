# encoding='utf-8'
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_dast import (
    init_engine_dast,

)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageResultPipeline,
)


def runner_engine_dast():
    pass

if __name__ == "__main__":
    init_engine_dast()
