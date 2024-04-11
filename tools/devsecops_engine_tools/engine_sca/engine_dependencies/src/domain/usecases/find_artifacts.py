import os
import tarfile
import subprocess
import shutil
import re

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class FindArtifacts:
    def __init__(
        self,
        working_dir,
        pattern,
    ):
        self.working_dir = working_dir
        self.pattern = pattern

    def find_packages(self, pattern, working_dir):
        npm_packages = []
        py_packages = []
        ext_files = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)
        search_path = os.path.expanduser("~")
        for root, dirs, files in os.walk(search_path):
            components = root.split(os.path.sep)
            if not ("node_modules" in components) and not (
                "site-packages" in components
            ):
                if "site-packages" in dirs:
                    py_packages.append(os.path.join(root, "site-packages"))
                if ("node_modules" in dirs) and (working_dir in root):
                    npm_packages.append(os.path.join(root, "node_modules"))
                if working_dir in root:
                    for file in files:
                        if extension_pattern.search(file):
                            ext_files.append(os.path.join(root, file))
        return npm_packages, py_packages, ext_files

    def get_recent_package(self, packages):
        recent_package = None
        recent_time = 0
        for path in packages:
            created_time = os.path.getctime(path)
            if created_time > recent_time:
                recent_time = created_time
                recent_package = path
        return recent_package

    def compress_and_mv(self, tar_path, package):
        try:
            if os.path.exists(tar_path):
                os.remove(tar_path)
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

        npm_packages, py_packages, ext_files = self.find_packages(
            self.pattern, self.working_dir
        )

        if len(npm_packages):
            npm_recent = self.get_recent_package(npm_packages)
            tar_path = os.path.join(dir_to_scan_path, "node_modules.tar")
            self.compress_and_mv(tar_path, npm_recent)

        if len(py_packages):
            py_recent = self.get_recent_package(py_packages)
            tar_path = os.path.join(dir_to_scan_path, "site-packages.tar")
            self.compress_and_mv(tar_path, py_recent)

        if len(ext_files):
            self.move_files(dir_to_scan_path, ext_files)

        return dir_to_scan_path
