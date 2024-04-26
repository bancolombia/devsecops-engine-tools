from enum import Enum


MESSAGE_VALUE = "El valor"
MESSAGE_NIL = "no puede ser nulo"


class CheckovConfigEnum(Enum):
    "https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html"
    BRANCH = "branch"
    FRAMEWORK = "framework"
    CHECKS = "check"
    COMPACT = "compact"
    DIRECTORIES = "directory"
    QUIET = "quiet"
    OUTPUT = "output"
    SOFT_FAIL = "soft-fail"
    EVALUATE_VARIABLES = "evaluate-variables"
    EXTERNAL_CHECKS_DIR = "external-checks-dir"
    SKIP_CHECKS = "skip-check"
    DOCKER_IMAGE = "docker-image"
    DOCKERFILEPATH = "dockerfile-path"
    EXTERNAL_CHECKS_GIT = "external-checks-git"
    SKIP_DOWNLOAD = "skip-download"


class CheckovConfig:
    dict_confg_file = {}

    def __init__(
        self,
        path_config_file,
        config_file_name,
        directories,
        env,
        branch=None,
        framework=None,
        checks=None,
        compact=True,
        quiet=True,
        output="json",
        soft_fail=True,
        evaluate_variables=True,
        external_checks_dir=None,
        external_checks_git=None,
        skip_checks=None,
        skip_download=True,
    ):
        self.path_config_file = path_config_file
        self.config_file_name = config_file_name
        self.branch = branch
        self.checks = checks
        self.framework = framework
        self.compact = compact
        self.directories = directories
        self.quiet = quiet
        self.output = output
        self.soft_fail = soft_fail
        self.evaluate_variables = evaluate_variables
        self.external_checks_dir = external_checks_dir
        self.external_checks_git = external_checks_git
        self.skip_checks = skip_checks
        self.skip_download = skip_download
        self.env = env

    def create_config_dict(self):
        if self.framework is not None:
            self.dict_confg_file[CheckovConfigEnum.FRAMEWORK.value] = self.framework
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.FRAMEWORK.value + MESSAGE_NIL
            )
        if self.compact is not None:
            self.dict_confg_file[CheckovConfigEnum.COMPACT.value] = self.compact
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.COMPACT.value + MESSAGE_NIL
            )

        if self.quiet is not None:
            self.dict_confg_file[CheckovConfigEnum.QUIET.value] = self.quiet
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.QUIET.value + MESSAGE_NIL
            )

        if self.checks is not None:
            self.dict_confg_file[CheckovConfigEnum.CHECKS.value] = self.checks
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.CHECKS.value + MESSAGE_NIL
            )

        if self.output is not None:
            self.dict_confg_file[CheckovConfigEnum.OUTPUT.value] = self.output
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.OUTPUT.value + MESSAGE_NIL
            )

        if self.soft_fail is not None:
            self.dict_confg_file[CheckovConfigEnum.SOFT_FAIL.value] = self.soft_fail
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.CHECKS.value + MESSAGE_NIL
            )

        if self.directories is not None:
            self.dict_confg_file[CheckovConfigEnum.DIRECTORIES.value] = self.directories
        else:
            raise ValueError(
                MESSAGE_VALUE + CheckovConfigEnum.DIRECTORIES.value + MESSAGE_NIL
            )

        if self.evaluate_variables is not None:
            self.dict_confg_file[
                CheckovConfigEnum.EVALUATE_VARIABLES.value
            ] = self.evaluate_variables

        if self.external_checks_git is not None:
            self.dict_confg_file[
                CheckovConfigEnum.EXTERNAL_CHECKS_GIT.value
            ] = self.external_checks_git

        if self.external_checks_dir is not None:
            self.dict_confg_file[
                CheckovConfigEnum.EXTERNAL_CHECKS_DIR.value
            ] = self.external_checks_dir

        if self.skip_download is not None:
            self.dict_confg_file[
                CheckovConfigEnum.SKIP_DOWNLOAD.value
            ] = self.skip_download

        return self.dict_confg_file
