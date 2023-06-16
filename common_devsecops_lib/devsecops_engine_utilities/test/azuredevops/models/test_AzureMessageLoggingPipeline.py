import pytest
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageResultPipeline


@pytest.mark.parametrize(
    "pipeline_result, expected_output",
    [
        (AzureMessageResultPipeline.Failed, '##vso[task.complete result=Failed;]DONE'),
        (AzureMessageResultPipeline.SucceededWithIssues, '##vso[task.complete result=SucceededWithIssues;]DONE'),
        (AzureMessageResultPipeline.Succeeded, '##vso[task.complete result=Succeeded;]DONE'),
    ],
)
def test_azure_message_result_pipeline(pipeline_result, expected_output):
    assert pipeline_result.value == expected_output
