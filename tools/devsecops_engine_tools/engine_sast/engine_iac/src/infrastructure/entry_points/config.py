remote_config = """{
    "CHECKOV": {
        "VERSION": "2.3.296",
        "SEARCH_PATTERN": ["AW","NU"],
        "IGNORE_SEARCH_PATTERN" : ["_test"],
        "EXCLUSIONS_PATH" : "/SAST/IAC/Exclusions/Exclusions.json",
        "LEVEL_COMPLIANCE": {
            "dev": {"Critical": 0,"High": 1,"Medium": 2,"Low": 5},
            "qa": {"Critical": 0,"High": 1,"Medium": 2,"Low": 5},
            "pdn": {"Critical": 0,"High": 1,"Medium": 2,"Low": 5}
        },
        "RULES": {
            "RULES_DOCKER": {
                "CKV_DOCKER_1" : {
                    "checkID": "IAC-CKV-DOCKER-1 Ensure port 22 is not exposed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Medium",
                    "cvss" : ""
                },
                "CKV_DOCKER_3" : {
                    "checkID": "IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_DOCKER_4" : {
                    "checkID": "IAC-CKV-DOCKER-4 Ensure that COPY is used instead of ADD in Dockerfiles",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Medium",
                    "cvss" : ""
                },
                "CKV_DOCKER_8" : {
                    "checkID": "IAC-CKV-DOCKER-8 Ensure the last USER is not root",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                }
            },
            "RULES_K8S": {
                "CKV_K8S_8" : {
                    "checkID": "IAC-CKV_K8S_8 Liveness Probe Should be Configured",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Low",
                    "cvss" : ""
                },
                "CKV_K8S_9" : {
                    "checkID": "IAC-CKV_K8S_9 Readiness Probe Should be Configured",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Low",
                    "cvss" : ""
                },
				"CKV_K8S_10" : {
                    "checkID": "IAC-CKV_K8S_10 Ensure CPU request is set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
				"CKV_K8S_11" : {
                    "checkID": "IAC-CKV_K8S_11 Ensure CPU limits are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
				"CKV_K8S_12" : {
                    "checkID": "IAC-CKV_K8S_12 Ensure memory requests are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
				"CKV_K8S_13" : {
                    "checkID": "IAC-CKV_K8S_13 Ensure memory limits are set",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_16": {
                    "checkID": "IAC-CKV_K8S_16 Container should not be privileged",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_17": {
                    "checkID": "IAC-CKV_K8S_17 Containers should not share the host process ID namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_18": {
                    "checkID": "IAC-CKV_K8S_18 Containers should not share the host IPC namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_19": {
                    "checkID": "IAC-CKV_K8S_19 Containers should not share the host network namespace",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_20": {
                    "checkID": "IAC-CKV_K8S_20 Containers should not run with allowPrivilegeEscalation",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_21": {
                    "checkID": "IAC-CKV_K8S_21 The default namespace should not be used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_22": {
                    "checkID": "IAC-CKV_K8S_22 Use read-only filesystem for containers where possible",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_23": {
                    "checkID": "IAC-CKV_K8S_23 Minimize the admission of root containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_26": {
                    "checkID": "IAC-CKV_K8S_26 Do not specify hostPort unless absolutely necessary",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Medium",
                    "cvss" : ""
                },
                "CKV_K8S_28": {
                    "checkID": "IAC-CKV_K8S_28 Minimize the admission of containers with the NET_RAW capability",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Critical",
                    "cvss" : ""
                },
                "CKV_K8S_29": {
                    "checkID": "IAC-CKV_K8S_29 Apply security context to your pods and containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_30": {
                    "checkID": "IAC-CKV_K8S_30 Apply security context to your containers",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_33": {
                    "checkID": "IAC-CKV_K8S_33 Ensure the Kubernetes dashboard is not deployed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_34": {
                    "checkID": "IAC-CKV_K8S_34 Ensure that Tiller (Helm v2) is not deployed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_37": {
                    "checkID": "IAC-CKV_K8S_37 Minimize the admission of containers with capabilities assigned",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_38": {
                    "checkID": "IAC-CKV_K8S_38 Ensure that Service Account Tokens are only mounted where necessary",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_39": {
                    "checkID": "IAC-CKV_K8S_39 Do not use the CAP_SYS_ADMIN linux capability",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_41": {
                    "checkID": "IAC-CKV_K8S_41 Ensure that default service accounts are not actively used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_42": {
                    "checkID": "IAC-CKV_K8S_42 Ensure that default service accounts are not actively used",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_43": {
                    "checkID": "IAC-CKV_K8S_43 Image should use digest",
                    "environment": {
                        "dev": false,
                        "pdn": false,
                        "qa": false
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Medium",
                    "cvss" : ""
                },
                "CKV_K8S_49": {
                    "checkID": "IAC-CKV_K8S_49 Ensure the last USER is not root",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "Critical",
                    "cvss" : ""
                },
                "CKV_K8S_155": {
                    "checkID": "IAC-CKV_K8S_155 Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_156": {
                    "checkID": "IAC-CKV_K8S_156 Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_157": {
                    "checkID": "IAC-CKV_K8S_157 Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV_K8S_158": {
                    "checkID": "IAC-CKV_K8S_158 Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV2_K8S_1": {
                    "checkID": "IAC-CKV2_K8S_1 RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV2_K8S_2": {
                    "checkID": "IAC-CKV2_K8S_2 Granting ",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV2_K8S_3": {
                    "checkID": "IAC-CKV2_K8S_3 No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV2_K8S_4": {
                    "checkID": "IAC-CKV2_K8S_4 ServiceAccounts and nodes that can modify services/status may set the status.loadBalancer.ingress.ip field ",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                },
                "CKV2_K8S_5": {
                    "checkID": "IAC-CKV2_K8S_5 No ServiceAccount/Node should be able to read all secrets",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://URL_WIKI.com",
                    "severity": "High",
                    "cvss" : ""
                }
            }
        }
    }
}"""
