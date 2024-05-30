import os
import tarfile
import subprocess
import shutil
import re

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class FindArtifacts:
    def __init__(
        self,
        working_dir,
        pattern,
        packages,
    ):
        self.working_dir = working_dir
        self.pattern = pattern
        self.packages = packages

    def find_packages(self, pattern, packages, working_dir):
        packages_list = []
        files_list = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)
        for root, dirs, files in os.walk(working_dir):
            components = root.split(os.path.sep)
            flag = 0
            for package in packages:
                if not (package in components):
                    flag = 1
                    if package in dirs:
                        packages_list.append(os.path.join(root, package))
            if flag:
                for file in files:
                    if extension_pattern.search(file):
                        files_list.append(os.path.join(root, file))
        return packages_list, files_list

    def compress_and_mv(self, tar_path, package):
        try:
            with tarfile.open(tar_path, "w") as tar:
                tar.add(
                    package,
                    arcname=os.path.basename(package),
                    filter=lambda x: None if "/.bin/" in x.name else x,
                )
                logger.debug(f"File to scan: {tar_path}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during {package} compression: {e}")

    def move_files(self, dir_to_scan_path, finded_files):
        for file in finded_files:
            target = os.path.join(dir_to_scan_path, os.path.basename(file))
            shutil.copy2(file, target)
            logger.debug(f"File to scan: {file}")

    def find_artifacts(self):
        dir_to_scan_path = os.path.join(self.working_dir, "dependencies_to_scan")
        if os.path.exists(dir_to_scan_path):
            shutil.rmtree(dir_to_scan_path)
        os.makedirs(dir_to_scan_path)

        packages_list, files_list = self.find_packages(
            self.pattern, self.packages, self.working_dir
        )

        for package in packages_list:
            tar_path = os.path.join(
                dir_to_scan_path,
                "pkg"
                + str(packages_list.index(package) + 1)
                + "_"
                + os.path.basename(package)
                + ".tar",
            )
            self.compress_and_mv(tar_path, package)

        if len(files_list):
            self.move_files(dir_to_scan_path, files_list)

        files = os.listdir(dir_to_scan_path)
        files = [
            file
            for file in files
            if os.path.isfile(os.path.join(dir_to_scan_path, file))
        ]
        if files:
            files_string = ", ".join(files)
            logger.debug(f"Files to scan: {files_string}")
            print(f"Files to scan: {files_string}")

        return dir_to_scan_path
