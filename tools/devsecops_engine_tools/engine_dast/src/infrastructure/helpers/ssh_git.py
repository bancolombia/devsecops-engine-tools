import platform
import os
import json
import argparse
import sys
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_utilities.ssh.managment_private_key import (
    create_ssh_private_file,
    add_ssh_private_key,
    decode_base64,
    config_knowns_hosts,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--github_token", type=str, required=True, help="")
    parser.add_argument("--repository_ssh_private_key", required=False, help="")
    parser.add_argument("--repository_ssh_password", required=False, help="")

    args = parser.parse_args()
    return {
        "github_token": args.github_token,
        "repository_ssh_private_key": args.repository_ssh_private_key,
        "repository_ssh_password": args.repository_ssh_password,
    }


TOOL = "CHECKOV"
json_data = """
{
    "CHECKOV": {
        "VERSION": "2.3.296",
        "SEARCH_PATTERN": [
            "AW",
            "NU"
        ],
        "IGNORE_SEARCH_PATTERN": [
            "test",
            "_ACE",
            "_ACE11",
            "NU0212001_Security_Services_MR"
        ],
        "USE_EXTERNAL_CHECKS_GIT": "False",
        "EXTERNAL_CHECKS_GIT": "git@github.com:bancolombia/NU0429001_devsecops_engine.git//tools",
        "EXTERNAL_GIT_SSH_HOST": "github.com",
        "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
        "USE_EXTERNAL_CHECKS_DIR": "True",
        "EXTERNAL_DIR_OWNER": "bancolombia",
        "EXTERNAL_DIR_REPOSITORY": "NU0429001_devsecops_engine",
        "EXTERNAL_DIR_ASSET_NAME": "tools/devsecops_engine_tools",
        "EXCLUSIONS_PATH": "/SAST/IAC/Exclusions/Exclusions.json",
        "MESSAGE_INFO_SAST_RM": "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199",
        "THRESHOLD": {
            "VULNERABILITY": {
                "Critical": 1,
                "High": 8,
                "Medium": 10,
                "Low": 15
            },
            "COMPLIANCE": {
                "Critical": 1
            }
        },
        "RULES": {
            "RULES_DOCKER": {
                "CKV_DOCKER_1": {
                    "checkID": "IAC-CKV-DOCKER-1 Ensure port 22 is not exposed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_DOCKER_3": {
                    "checkID": "IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_DOCKER_4": {
                    "checkID": "IAC-CKV-DOCKER-4 Ensure that COPY is used instead of ADD in Dockerfiles",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Medium",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_DOCKER_8": {
                    "checkID": "IAC-CKV-DOCKER-8 Ensure the last USER is not root",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                }
            },
            "RULES_K8S": {
                "CKV_K8S_8": {
                    "checkID": "IAC-CKV_K8S_8 Liveness Probe Should be Configured",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_9": {
                    "checkID": "IAC-CKV_K8S_9 Readiness Probe Should be Configured",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_10": {
                    "checkID": "IAC-CKV_K8S_10 Ensure CPU request is set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_11": {
                    "checkID": "IAC-CKV_K8S_11 Ensure CPU limits are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_12": {
                    "checkID": "IAC-CKV_K8S_12 Ensure memory requests are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_13": {
                    "checkID": "IAC-CKV_K8S_13 Ensure memory limits are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_16": {
                    "checkID": "IAC-CKV_K8S_16 Container should not be privileged",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_17": {
                    "checkID": "IAC-CKV_K8S_17 Containers should not share the host process ID namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_18": {
                    "checkID": "IAC-CKV_K8S_18 Containers should not share the host IPC namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_19": {
                    "checkID": "IAC-CKV_K8S_19 Containers should not share the host network namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_20": {
                    "checkID": "IAC-CKV_K8S_20 Containers should not run with allowPrivilegeEscalation",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_21": {
                    "checkID": "IAC-CKV_K8S_21 The default namespace should not be used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_22": {
                    "checkID": "IAC-CKV_K8S_22 Use read-only filesystem for containers where possible",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_23": {
                    "checkID": "IAC-CKV_K8S_23 Minimize the admission of root containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_26": {
                    "checkID": "IAC-CKV_K8S_26 Do not specify hostPort unless absolutely necessary",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Medium",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_28": {
                    "checkID": "IAC-CKV_K8S_28 Minimize the admission of containers with the NET_RAW capability",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_29": {
                    "checkID": "IAC-CKV_K8S_29 Apply security context to your pods and containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_30": {
                    "checkID": "IAC-CKV_K8S_30 Apply security context to your containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_33": {
                    "checkID": "IAC-CKV_K8S_33 Ensure the Kubernetes dashboard is not deployed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_34": {
                    "checkID": "IAC-CKV_K8S_34 Ensure that Tiller (Helm v2) is not deployed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_37": {
                    "checkID": "IAC-CKV_K8S_37 Minimize the admission of containers with capabilities assigned",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_38": {
                    "checkID": "IAC-CKV_K8S_38 Ensure that Service Account Tokens are only mounted where necessary",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_39": {
                    "checkID": "IAC-CKV_K8S_39 Do not use the CAP_SYS_ADMIN linux capability",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_41": {
                    "checkID": "IAC-CKV_K8S_41 Ensure that default service accounts are not actively used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_42": {
                    "checkID": "IAC-CKV_K8S_42 Ensure that default service accounts are not actively used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_43": {
                    "checkID": "IAC-CKV_K8S_43 Image should use digest",
                    "environment": {
                        "dev": false,
                        "pdn": false,
                        "qa": false
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Medium",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_49": {
                    "checkID": "IAC-CKV_K8S_49 Minimize wildcard use in Roles and ClusterRoles",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_155": {
                    "checkID": "IAC-CKV_K8S_155 Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_156": {
                    "checkID": "IAC-CKV_K8S_156 Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_157": {
                    "checkID": "IAC-CKV_K8S_157 Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_158": {
                    "checkID": "IAC-CKV_K8S_158 Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV2_K8S_1": {
                    "checkID": "IAC-CKV2_K8S_1 RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV2_K8S_2": {
                    "checkID": "IAC-CKV2_K8S_2 Granting",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV2_K8S_3": {
                    "checkID": "IAC-CKV2_K8S_3 No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV2_K8S_4": {
                    "checkID": "IAC-CKV2_K8S_4 ServiceAccounts and nodes that can modify services/status may set the status.loadBalancer.ingress.ip field",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV2_K8S_5": {
                    "checkID": "IAC-CKV2_K8S_5 No ServiceAccount/Node should be able to read all secrets",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
                },
                "CKV_K8S_BC_1": {
                    "checkID": "IAC-CKV_K8S_BC_1 k8s resources has compliance tags",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Low",
                    "cvss": "",
                    "category": "Compliance"
                },
                "CKV_K8S_BC_2": {
                    "checkID": "IAC-CKV_K8S_BC_2 k8s resources has topologySpreadConstraints configuration",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Low",
                    "cvss": "",
                    "category": "Compliance"
                }
            }
        }
    }
}

"""
json_data = json.loads(json_data)
config_tool = ConfigTool(json_data, TOOL)


class SshTester:
    def configurate_external_checks_local(self, config_tool: ConfigTool, secret_tool):
        agent_env = None
        try:
            if secret_tool is None:
                print("Secrets manager is not enabled to configure external checks")
            else:
                if (
                    config_tool.use_external_checks_git == "True"
                    and platform.system()
                    in (
                        "Linux",
                        "Darwin",
                    )
                ):
                    config_knowns_hosts(
                        config_tool.repository_ssh_host,
                        config_tool.repository_public_key_fp,
                    )
                    ssh_key_content = decode_base64(
                        secret_tool, "repository_ssh_private_key"
                    )
                    ssh_key_file_path = "/tmp/ssh_key_file"
                    create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                    ssh_key_password = decode_base64(
                        secret_tool, "repository_ssh_password"
                    )
                    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

                # Create configuration dir external checks
                if config_tool.use_external_checks_dir == "True":
                    github_api = GithubApi(secret_tool["github_token"])
                    github_api.download_latest_release_assets(
                        config_tool.external_dir_owner,
                        config_tool.external_dir_repository,
                        "/tmp",
                    )

        except Exception as ex:
            print(f"An error ocurred configuring external checks {ex}")
        return agent_env

    def configurate_external_checks(self, config_tool: ConfigTool, secret_tool):
        agent_env = None
        try:
            if secret_tool is None:
                print("Secrets manager is not enabled to configure external checks")
            else:
                if (
                    config_tool.use_external_checks_git == "True"
                    and platform.system()
                    in (
                        "Linux",
                        "Darwin",
                    )
                ):
                    config_knowns_hosts(
                        config_tool.repository_ssh_host,
                        config_tool.repository_public_key_fp,
                    )
                    ssh_key_content = decode_base64(
                        secret_tool, "repository_ssh_private_key"
                    )
                    ssh_key_file_path = "/tmp/ssh_key_file"
                    create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                    ssh_key_password = decode_base64(
                        secret_tool, "repository_ssh_password"
                    )
                    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

                # Create configuration dir external checks
                if config_tool.use_external_checks_dir == "True":
                    github_api = GithubApi(secret_tool["github_token"])
                    github_api.download_latest_release_assets(
                        config_tool.external_dir_owner,
                        config_tool.external_dir_repository,
                        "/tmp",
                    )

        except Exception as ex:
            print(f"An error ocurred configuring external checks {ex}")
        return agent_env


if __name__ == "__main__":
    ruta_directorio = "/tmp"
    print("\n\n\n TMP  ANTES \n\n\n")
    contenido_directorio = os.listdir(ruta_directorio)

    # Imprime el contenido del directorio
    for archivo in contenido_directorio:
        print(archivo)
    args = get_inputs_from_cli(sys.argv[1:])
    secret_tool = {
        "github_token": args["github_token"],
        "repository_ssh_private_key": args["repository_ssh_private_key"],
        "repository_ssh_password": args["repository_ssh_password"],
    }
    sshTester = SshTester()
    sshTester.configurate_external_checks_local(config_tool, secret_tool)
    # Especifica la ruta del directorio
    print("\n\n\n TMP  DESPUES \n\n\n")

    # Usa listdir() para obtener una lista de los nombres de los archivos en el directorio
    contenido_directorio = os.listdir(ruta_directorio)

    # Imprime el contenido del directorio
    for archivo in contenido_directorio:
        print(archivo)
