exclusion = """{
	"All": {
        "SCA": [
			{
				"id": "XRAY-521541",
				"where": "all",
				"cve_id": "CVE-2023-29405",
				"create_date" : "10112023",
				"expired_date": "18112023",
				"severity": "HIGH",
				"hu": "4338704"
            }
        ],
        "CHECKOV": [
			{
				"id": "XRAY-52154",
                "where": "all",
				"cve_id": "CVE-2023-29405",
				"create_date" : "18112023",
				"expired_date": "undefined",
				"severity": "LOW",
				"hu": "4338704"
			},
			{
            	"id": "CKV2_AWS_123",
                "where": "all",
				"cve_id": "N.A",
				"create_date" : "18112023",
				"expired_date": "18032024",
				"severity": "LOW",
				"hu": "4338704"
			},
            {
				"id": "CKV_K8S_37",
                "where": "all",
				"cve_id": "N.A",
				"create_date" : "18112023",
				"expired_date": "18032024",
				"severity": "LOW",
				"hu": "4338704"
			}
        ]
	},
	"AW11111111_ProyectoEjemplo": {
		"SCA": [
			{
				"id": "XRAY-521541",
                "where": "componente",
				"cve_id": "CVE-2023-29405",
				"create_date" : "10112023",
				"expired_date": "18112023",
				"severity": "HIGH",
				"hu": "4338704"
			}
		],
		"CHECKOV": [
			{
				"id": "XRAY-521541",
                "where": "app.yaml",
				"cve_id": "CVE-2023-29405",
				"create_date" : "18112023",
				"expired_date": "undefined",
				"severity": "LOW",
				"hu": "4338704"
			},
			{
				"id": "CKV2_AWS_123",
				"where": "all",
				"cve_id": "N.A",
				"create_date" : "18112023",
				"expired_date": "18032024",
				"severity": "LOW",
				"hu": "4338704"
			},
			{
				"id": "CKV_DOCKER_4",
				"where": "all",
				"cve_id": "N.A",
				"create_date" : "18112023",
				"expired_date": "18032024",
				"severity": "LOW",
				"hu": "4338704"
			}
		]
	}
}"""
