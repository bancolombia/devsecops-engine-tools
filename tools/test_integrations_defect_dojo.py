from devsecops_engine_tools.engine_utilities.defect_dojo import DefectDojo, ImportScanRequest, Connect, Finding
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.printers import Printers
from tabulate import tabulate

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()
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


def validate_response(response, **kwargs):
    table = None
    if hasattr(response, "url"):
        # end_point, description, status, result,
        table = [kwargs.get("end_point"), kwargs.get("scan_type"), "OK", response.url]
    elif kwargs.get("scan_type"):
        table = [kwargs.get("end_point"), kwargs.get("scan_type"), "Error", "None"]
    elif kwargs.get("end_point") in ["finding.close"]:
        if hasattr(response, "status_code"):
            table = [
                kwargs.get("end_point"),
                kwargs.get("description"),
                "OK" if response.status_code == 200 else "Error",
                "None",
            ]
    elif kwargs.get("end_point") in ["finding.get"]:
        table = [
            kwargs.get("end_point"),
            kwargs.get("description"),
            "OK" if type(response.count) == int else "Error",
            "None",
        ]
    return table


if __name__ == "__main__":
    table = []
    try:
        if settings.INTEGRATION_TEST:
            """test integration Aws security Finding"""
            Printers.print_title("AWS Security Finding Format (ASFF) Scan")
            response = import_scan(
                scan_type="AWS Security Finding Format (ASFF) Scan", file_path=f"{path_file}/aws_security_finding.json"
            )
            logger.debug(f"response: {response}")
            table.append(validate_response(response, scan_type="AWS Security Hub", end_point="impor_scan"))

            Printers.print_title("JFrog Xray On Demand Binary Scan")
            response = import_scan(
                scan_type="JFrog Xray On Demand Binary Scan",
                file_path=f"{path_file}/jfrog-xray_on_demand_binary_scan.json",
            )
            logger.debug(f"response: {response}")
            table.append(validate_response(response, scan_type="Jfrog Xray", end_point="impor_scan"))

            # test integration Checkov
            Printers.print_title("Checkov Scan")
            response = import_scan(scan_type="Checkov Scan", file_path=f"{path_file}/checkov.json")
            table.append(validate_response(response, scan_type="Checkov Scan", end_point="impor_scan"))

            """ test integration Twistlock Image Scan Json """
            Printers.print_title("Twistlock Image Scan JSON")
            response = import_scan(scan_type="Twistlock Image Scan", file_path=f"{path_file}/twistlock.json")
            table.append(validate_response(response, scan_type="Twistlock Image Scan", end_point="impor_scan json"))

            """ test integration Twistlock Image Scan Csv"""
            Printers.print_title("Twistlock Image Scan CSV")
            response = import_scan(scan_type="Twistlock Image Scan", file_path=f"{path_file}/twistlock.csv")
            table.append(validate_response(response, scan_type="Twistlock Image Scan", end_point="impor_scan csv"))

            """test integrations Sarif Scan"""
            Printers.print_title("Sarif Scan")
            response = import_scan(scan_type="SARIF", file_path=f"{path_file}/sarif_scan.sarif")
            table.append(validate_response(response, scan_type="Sarif Scan", end_point="impor_scan sarif"))

            """test SonarQuebe"""
            Printers.print_title("SonarQube API Import")
            response = import_scan(scan_type="SonarQube API Import")
            logger.debug(f"SonarQube Api Import: {response}")
            table.append(validate_response(response, scan_type="SonarQube", end_point="impor_scan"))

            """test get finding"""
            session = SessionManager(token=settings.TOKEN_DEFECT_DOJO, host=settings.HOST_DEFECT_DOJO)
            Printers.print_title("Get Finding")
            response = Finding.get_finding(session=session, risk_accepted=True)
            logger.debug(f"Finding get {response}")
            table.append(validate_response(response, end_point="finding.get"))

            """test integration Finding close"""
            Printers.print_title("Finding Close")
            response = Finding.close_finding(session, unique_id_from_tool="1")
            logger.debug(f"Finding_close: {response}")

            table.append(validate_response(response, end_point="finding.close"))
            print(tabulate(table, headers=["End_point", "Description", "Status", "Result"]))
            if any(item[2] == "Error" for item in table):
                logger.warning("Warning! Errors were found in the integration")
                logger.debug('"##vso[task.complete result=SucceededWithIssues;]DONE"')

        else:
            logger.warning("Test integration disable")

    except Exception as e:
        logger.error(e)
        raise ApiError(e)
