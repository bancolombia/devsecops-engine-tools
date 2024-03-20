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

    def find_node_modules(self, working_dir):
        for root, dirs, files in os.walk(working_dir):
            if "node_modules" in dirs:
                return os.path.join(root, "node_modules")
        return None

    def compress_and_mv(self, npm_modules_path, dir_to_scan_path):
        try:
            tar_path = os.path.join(dir_to_scan_path, "node_modules.tar")
            if os.path.exists(tar_path):
                os.remove(tar_path)
            with tarfile.open(tar_path, "w") as tar:
                tar.add(
                    npm_modules_path,
                    arcname=os.path.basename(npm_modules_path),
                    filter=lambda x: None if "/.bin/" in x.name else x,
                )
                logger.debug(f"File to scan: {tar_path}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during npm_modules compression: {e}")

    def find_by_extension(self, pattern, working_dir, dir_to_scan_path, excluded_dir):
        finded_files = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)

        for root, dirs, files in os.walk(working_dir):
            if not (excluded_dir in root) or excluded_dir == "":
                for file in files:
                    if extension_pattern.search(file):
                        ruta_completa = os.path.join(root, file)
                        finded_files.append(ruta_completa)

        for file in finded_files:
            target = os.path.join(dir_to_scan_path, os.path.basename(file))
            shutil.copy2(file, target)
            logger.debug(f"File to scan: {file}")

    def find_artifacts(self):
        dir_to_scan_path = os.path.join(self.working_dir, "dependencies_to_scan")
        if os.path.exists(dir_to_scan_path):
            shutil.rmtree(dir_to_scan_path)
        os.makedirs(dir_to_scan_path)

        npm_modules_path = self.find_node_modules(self.working_dir)

        excluded_dir = ""
        if npm_modules_path:
            self.compress_and_mv(npm_modules_path, dir_to_scan_path)
            excluded_dir = npm_modules_path

        self.find_by_extension(
            self.pattern, self.working_dir, dir_to_scan_path, excluded_dir
        )

        return dir_to_scan_path
