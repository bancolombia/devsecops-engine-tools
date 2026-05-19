import json
from datetime import datetime

from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)


SEVERITY_MAP = {
    "unimportant": "low",
    "unassigned": "low",
    "negligible": "low",
    "not yet assigned": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
}


def deserialize_twistcli_findings(image_scanned, module, tool_name):
    list_open_vulnerabilities = []
    with open(image_scanned, "rb") as file:
        json_data = json.loads(file.read())
        console_url = json_data.get("consoleURL", False)
        if console_url:
            print(f"Console URL: {console_url}")

        vulnerabilities_data = (
            json_data["results"][0]["vulnerabilities"]
            if "vulnerabilities" in json_data["results"][0]
            else []
        )

        vulnerabilities = [
            Finding(
                id=vul.get("id", ""),
                cvss=float(vul.get("cvss", 0.0)),
                where=vul.get("packageName", "") + ":" + vul.get("packageVersion", ""),
                description=vul.get("description", "")[:150],
                severity=SEVERITY_MAP.get(vul.get("severity", ""), ""),
                identification_date=datetime.strptime(
                    vul.get("discoveredDate", ""), "%Y-%m-%dT%H:%M:%S%z"
                ),
                published_date_cve=vul.get("publishedDate", "").replace("Z", "+00:00"),
                module=module,
                category=Category.VULNERABILITY,
                requirements=vul.get("status", ""),
                tool=tool_name,
            )
            for vul in vulnerabilities_data
        ]

        list_open_vulnerabilities.extend(vulnerabilities)

    return list_open_vulnerabilities
