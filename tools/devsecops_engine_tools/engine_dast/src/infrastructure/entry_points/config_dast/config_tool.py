config_tool_local = {
    "NUCLEI": {
        "VERSION": "2.3.296",
        "SEARCH_PATTERN": ["AW", "NU"],
        "IGNORE_SEARCH_PATTERN": [
            "test",
            "_ACE",
            "_ACE11",
            "NU0212001_Security_Services_MR",
        ],
        "USE_EXTERNAL_CHECKS_GIT": "False",
        "EXTERNAL_CHECKS_GIT": "git@github.com:BCSCode/DevSecOps_Checks_IaC.git//rules",
        "EXTERNAL_GIT_SSH_HOST": "github.com",
        "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
        "USE_EXTERNAL_CHECKS_DIR": "True",
        "EXTERNAL_DIR_OWNER": "BCSCode",
        "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks_IaC",
        "EXTERNAL_DIR_ASSET_NAME": "rules/kubernetes",
        "EXCLUSIONS_PATH": "/SAST/IAC/Exclusions/Exclusions.json",
        "MESSAGE_INFO_DAST": "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199",
        "THRESHOLD": {
            "VULNERABILITY": {"Critical": 1, "High": 8, "Medium": 10, "Low": 15},
            "COMPLIANCE": {"Critical": 1},
        },
        "RULES": {
            "RULES_DOCKER": {
                "CKV_DOCKER_1": {
                    "checkID": "IAC-CKV-DOCKER-1 Ensure port 22 is not exposed",
                    "environment": {"dev": True, "pdn": True, "qa": True},
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability",
                },
                "CKV_DOCKER_3": {
                    "checkID": "IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
                    "environment": {"dev": True, "pdn": True, "qa": True},
                    "guideline": "https://bancolombia.sharepoint.com/:x:/r/teams/SeguridaddeTI-DevSecOps/Documentos%20compartidos/General/Pr%C3%A1cticas%20automatizadas%20de%20seguridad/MegaEngine/analisis%20estatico/Analisis%20est%C3%A1tico%20de%20Infraestructura%20(engine-iac)/Docker_k8s_Rules.xlsx?d=w65b6553bc4574805b31e57f4326d2dc7&csf=1&web=1&e=k0nmNU",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability",
                },
            }
        },
    }
}
