exclusion = """{
	"All": {
        "SCA": {
            "Exclusions": [
                {
                    "check_id": "XRAY-521541",
                    "Cve_Id": "CVE-2023-29405",
                    "Create_Date" : "10112023",
                    "Expired_Date": "18112023",
                    "severity": "HIGH",
                    "HU": "4338704"
                }
            ]
        },
        "CHECKOV": {
            "Exclusions": [
                {
                    "check_id": "XRAY-521541",
                    "Cve_Id": "CVE-2023-29405",
                    "Create_Date" : "18112023",
                    "Expired_Date": "undefined",
                    "severity": "LOW",
                    "HU": "4338704"
                },
                {
                    "check_id": "CKV2_AWS_123",
                    "Cve_Id": "N.A",
                    "Create_Date" : "18112023",
                    "Expired_Date": "18032024",
                    "severity": "LOW",
                    "HU": "4338704"
                }
            ]
        }
	},
	"AW11111111_ProyectoEjemplo": {
			"SCA": {
				"Exclusions": [
					{
						"check_id": "XRAY-521541",
						"Cve_Id": "CVE-2023-29405",
						"Create_Date" : "10112023",
						"Expired_Date": "18112023",
						"severity": "HIGH",
						"HU": "4338704"
					}
				]
			},
			"CHECKOV": {
				"Exclusions": [
					{
						"check_id": "XRAY-521541",
						"Cve_Id": "CVE-2023-29405",
						"Create_Date" : "18112023",
						"Expired_Date": "undefined",
						"severity": "LOW",
						"HU": "4338704"
					},
					{
						"check_id": "CKV2_AWS_123",
						"Cve_Id": "N.A",
						"Create_Date" : "18112023",
						"Expired_Date": "18032024",
						"severity": "LOW",
						"HU": "4338704"
					}
				]
			}
	}
}"""
