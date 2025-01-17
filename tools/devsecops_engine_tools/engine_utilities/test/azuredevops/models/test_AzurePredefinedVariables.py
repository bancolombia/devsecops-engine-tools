import pytest
import os
from devsecops_engine_tools.engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    BuildVariables,
    ReleaseVariables,
    AgentVariables,
    VMVariables
)


@pytest.mark.parametrize(
    "enum_class, expected_env_name, expected_value",
    [
        (SystemVariables.System_AccessToken, "SYSTEM_ACCESSTOKEN", "AccessTokenValue"),
        (SystemVariables.System_CollectionId, "SYSTEM_COLLECTIONID", "CollectionIdValue"),
        (
            SystemVariables.System_DefaultWorkingDirectory,
            "SYSTEM_DEFAULTWORKINGDIRECTORY",
            "DefaultWorkingDirectoryValue",
        ),
        (BuildVariables.Build_DefinitionName, "BUILD_DEFINITIONNAME", "DefinitionNameValue"),
        (BuildVariables.Build_Repository_Name, "BUILD_REPOSITORY_NAME", "RepositoryNameValue"),
        (BuildVariables.Build_SourceBranch, "BUILD_SOURCEBRANCH", "SourceBranchValue"),
        (ReleaseVariables.Artifact_Path, "ARTIFACT_PATH", "ArtifactPathValue"),
        (AgentVariables.Agent_WorkFolder, "AGENT_WORKFOLDER", "AgentWorkFolder"),
        (AgentVariables.Agent_BuildDirectory, "AGENT_BUILDDIRECTORY", "AgentBuildDirectory"),
        (VMVariables.Vm_Product_Type_Name, "VM_PRODUCT_TYPE_NAME", "ProductTypeName"),
        (VMVariables.Vm_Product_Name, "VM_PRODUCT_NAME", "ProductName"),
        (VMVariables.Vm_Product_Description, "VM_PRODUCT_DESCRIPTION", "ProductDescription"),
    ],
)
def test_enum_env_name(monkeypatch, enum_class, expected_env_name, expected_value):
    monkeypatch.setattr(os.environ, "get", lambda _: expected_value)
    assert enum_class.env_name == expected_env_name
    assert enum_class.value() == expected_value
