from devsecops_engine_utilities.defect_dojo import DefectDojo, ImportScanRequest, Connect, Finding
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities import settings


path_file = settings.DEVSECOPS_ENGINE_UTILITIES_PATH
work_directory = "/defect_dojo/test/files/request_file"
path_file = path_file + work_directory


def import_scan(scan_type, file_path=""):
    request: ImportScanRequest = Connect.cmdb(
        cmdb_mapping=settings.CMDB_MAPPING,
        compact_remote_config_url=settings.COMPACT_REMOTE_CONFIG_URL,
        personal_access_token=settings.PERSONAL_ACCESS_TOKEN,
        token_cmdb=settings.TOKEN_CMDB,
        host_cmdb=settings.HOST_CMDB,
        expression=settings.EXPRESSION,
        token_defect_dojo=settings.TOKEN_DEFECT_DOJO,
        host_defect_dojo=settings.HOST_DEFECT_DOJO,
        scan_type=scan_type,
        engagement_name=settings.ENGAGEMENT_NAME,
        file=file_path,
        tags=settings.TAGS,
        branch_tag=settings.BRANCH_TAG,
    )

    response = DefectDojo.send_import_scan(request)
    return response


if __name__ == "__main__":
    if settings.INTEGRATION_TEST:
        # # test integration Aws security Finding
        response = import_scan(
            scan_type="AWS Security Finding Format (ASFF) Scan", file_path=f"{path_file}/aws_security_finding.json"
        )
        print(response)
        assert hasattr(response, "test_url")
        assert response.engagement_name == settings.ENGAGEMENT_NAME
        assert response.scan_type == "AWS Security Finding Format (ASFF) Scan"
        # # test integration Xray
        response = import_scan(scan_type="Jfrog Xray On Demand Binary Scan", file_path=f"{path_file}/xray.json")
        assert hasattr(response, "test_url")
        assert response.engagement_name == settings.ENGAGEMENT_NAME
        assert response.scan_type == "Jfrog Xray On Demand Binary Scan"

        # # test integration Checkov
        response = import_scan(scan_type="Checkov Scan", file_path=f"{path_file}/checkov.json")
        assert hasattr(response, "test_url")
        assert response.engagement_name == settings.ENGAGEMENT_NAME
        assert response.scan_type == "Checkov Scan"

        # # test SonarQuebe
        response = import_scan(scan_type="SonarQube API Import")
        assert hasattr(response, "test_url")
        assert response.engagement_name == settings.ENGAGEMENT_NAME
        assert response.scan_type == "SonarQube API Import"

        ## test integration Finding close
        session = SessionManager(token=settings.TOKEN_DEFECT_DOJO, host="http://localhost:8000/")
        response = Finding.close_finding(session, unique_id_from_tool="1")
    else:
        print("Test integration disable")
