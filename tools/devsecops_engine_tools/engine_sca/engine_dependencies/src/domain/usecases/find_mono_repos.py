import os


class FindMonoRepos:
    def __init__(
        self,
        pipeline_name,
    ):
        self.pipeline_name = pipeline_name

    def handle_find_mono_repo(self, pipeline_name):
        """
        Handle find mono repository dir.

        Return: String: Directory to scan.
        """
        current_dir = os.getcwd()
        pattern = "_MR_"
        if pattern in pipeline_name:
            mr_dir = pipeline_name.split(pattern)[1]
            mr_dir_path = os.path.join(current_dir, mr_dir)
            if os.path.isdir(mr_dir_path):
                return mr_dir_path

            for root, dirs, files in os.walk(current_dir):
                if mr_dir in dirs:
                    return os.path.join(root, mr_dir)

        return current_dir

    def process_find_mono_repo(self):
        """
        Process handle find mono repository dir.

        Return: String: Directory to scan.
        """
        return self.handle_find_mono_repo(
            self.pipeline_name,
        )
