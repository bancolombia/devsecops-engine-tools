import dataclasses

@dataclasses.dataclass
class SettingRepo:
    personal_access_token: str = ""
    remote_config_repo: str = ""
    remote_config_path: str = ""
    system_team_project_id: str = ""
    organization_url: str = ""
