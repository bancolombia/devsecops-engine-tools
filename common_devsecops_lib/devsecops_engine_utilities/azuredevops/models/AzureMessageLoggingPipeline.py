from enum import Enum

"""https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash """


class BaseEnum(Enum):
    def get_message(self, message: str):
        return self._value_ + message


class AzureMessageResultPipeline(Enum):
    Failed = "##vso[task.complete result=Failed;]DONE"
    SucceededWithIssues = "##vso[task.complete result=SucceededWithIssues;]DONE"
    Succeeded = "##vso[task.complete result=Succeeded;]DONE"


class AzureMessageLoggingPipeline(BaseEnum):
    WarningLogging = "##[warning]"
    ErrorLogging = "##[error]"
    SucceededLogging = "##[section]"
    InfoLogging = "##[command]"
