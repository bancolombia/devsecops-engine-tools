config_exclusions = {
    "authorizedDefinitionIds": ["33694"],
    "committer": ["svchca04@bancolombia.com.co", "Usuario Devops 04"],
    "All": {
        "SCA": [
            {
                "id": "XRAY-521541",
                "where": "all",
                "cve_id": "CVE-2023-29405",
                "create_date": "10112023",
                "expired_date": "18112023",
                "severity": "HIGH",
                "hu": "4338704",
            }
        ],
        "CHECKOV": [
            {
                "id": "CKV2_AWS_123",
                "where": "all",
                "cve_id": "N.A",
                "create_date": "18112023",
                "expired_date": "18032024",
                "severity": "LOW",
                "hu": "4338704",
            }
        ],
    },
    "AW11111111_ProyectoEjemplo": {
        "SCA": [
            {
                "id": "XRAY-521549",
                "where": "test",
                "cve_id": "CVE-2023-29405",
                "create_date": "10112023",
                "expired_date": "18112023",
                "severity": "HIGH",
                "hu": "4338704",
            }
        ],
        "CHECKOV": [
            {
                "id": "CKV2_AWS_124",
                "where": "app.yaml",
                "cve_id": "N.A",
                "create_date": "18112023",
                "expired_date": "18032024",
                "severity": "LOW",
                "hu": "4338704",
            }
        ],
    },
}
