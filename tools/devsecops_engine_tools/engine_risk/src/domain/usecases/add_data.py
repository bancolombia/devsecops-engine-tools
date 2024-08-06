import requests
import datetime
import io
import gzip
import csv

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class AddData:
    def __init__(
        self,
        findings,
    ):
        self.findings = findings

    @staticmethod
    def download_epss_data():
        base_url = "https://epss.cyentia.com/epss_scores-{}.csv.gz"
        date = datetime.datetime.now()
        attempts = 0
        while attempts < 2:
            formatted_date = date.strftime("%Y-%m-%d")
            url = base_url.format(formatted_date)
            response = requests.get(url)
            if response.status_code == 200:
                with gzip.open(io.BytesIO(response.content), "rt") as f:
                    data = f.read()
                logger.info(f"EPSS data downloaded for date: {formatted_date}")
                return data
            else:
                date -= datetime.timedelta(days=1)
                attempts += 1
        print("Could not find EPSS data from de last 2 days. Skipping add EPS data...")
        logger.error(
            "Could not find EPSS data from de last 2 days. Skipping add EPS data..."
        )
        return None

    def get_epss_dict(self, epss_data):
        epss_dict = {}
        csv_reader = csv.reader(io.StringIO(epss_data))
        for row in csv_reader:
            if len(row) >= 2:
                epss_dict[row[0]] = row[1]
        return epss_dict

    def add_data(self):
        needs_epss_update = any(
            finding.vul_id[:3] == "CVE" and finding.epss_score == 0
            for finding in self.findings
        )
        if needs_epss_update:
            epss_data = self.download_epss_data()
            if epss_data:
                epss_dict = self.get_epss_dict(epss_data)
                for finding in self.findings:
                    if finding.vul_id[:3] == "CVE" and finding.epss_score == 0:
                        finding.epss_score = epss_dict.get(finding.vul_id, 0)
        return self.findings
