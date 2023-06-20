import requests
import urllib3
from requests.auth import HTTPBasicAuth
from multipledispatch import dispatch


urllib3.disable_warnings()


class AzureDevopsRemoteConfig:
    """Info API in https://learn.microsoft.com/en-us/rest/api/azure/devopsgit/items/get?view=azure-devops-rest-7.0&tabs=HTTP
    ---------
    Parameters
    ----------
    api_version: str
        Version de la Api
    organization: str
        organization
    project: str
        project
    repository_id: str
        repository_id
    path_file: str
        path file to import
    user: str
        user azuredevops
    token: str
        token azureDevops

    Returns
    -------
    Response
        Response request http get file
    -------

    Use Example:

    test_AzureDevopsRemoteConfig= AzureDevopsRemoteConfig(api_version=7.0,verify_ssl=False)
    test_AzureDevopsRemoteConfig.organization = 'grupobancolombia'
    test_AzureDevopsRemoteConfig.project = 'Vicepresidencia Servicios de Tecnología'
    test_AzureDevopsRemoteConfig.repository_id = 'test_devsecops_engine'
    test_AzureDevopsRemoteConfig.path_file = '/examples_engine_apis_conf/devsecops_engine.json'
    test_AzureDevopsRemoteConfig.user = 'user'
    test_AzureDevopsRemoteConfig.token = 'token'
    response = test_AzureDevopsRemoteConfig.get_source_item()
    """

    def __init__(
        self,
        api_version,
        verify_ssl,
        organization=None,
        project=None,
        repository_id=None,
        path_file=None,
        user=None,
        token=None,
    ):
        self.API_VERSION = api_version
        self.VERIFY_SSL = verify_ssl
        self.organization = organization
        self.project = project
        self.repository_id = repository_id
        self.path_file = (path_file,)
        self.user = (user,)
        self.token = token

    def set_auth_basic(self, user, token):
        return HTTPBasicAuth(user, token)

    def send_get_request(self, url, headers, params, auth):
        rs = requests.get(url=url, auth=auth, headers=headers, verify=self.VERIFY_SSL, params=params)
        return rs

    def send_post_request(self, url, headers, params, auth):
        rs = requests.post(url=url, auth=auth, headers=headers, verify=self.VERIFY_SSL, params=params)
        return rs

    def set_headers(self):
        headers = {}
        headers["content-type"] = "application/json"
        headers["accept"] = "api-version={api_version}".format(api_version=self.API_VERSION)
        return headers

    def get_repos(self, organization, project):
        url = "https://dev.azure.com/{organization}/{project}/_apis/git/repositories?api-version={api_version}".format(
            organization=organization, project=project, api_version=self.API_VERSION
        )
        params = {"api-version": "{api_version}".format(api_version=self.API_VERSION)}
        return [url, params]

    @dispatch()
    def get_item(self):
        url = "https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository_id}/items".format(
            organization=self.organization,
            project=self.project,
            repository_id=self.repository_id,
        )
        params = {"api-version": self.API_VERSION}
        params["path"] = self.path_file
        return [url, params]

    @dispatch(str, str, str, str)
    def get_item(self, organization, project, repository_id, path_file):
        url = "https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository_id}/items".format(
            organization=organization, project=project, repository_id=repository_id
        )
        params = {"api-version": self.API_VERSION}
        params["path"] = path_file
        return [url, params]

    @dispatch(str, str, str, str, str, str, str, str, str, str, str, str, str, str, str)
    def get_item(
        self,
        organization,
        project,
        repository_id,
        path_file,
        scope_path,
        recursion_level,
        includeContentMetadata,
        latestProcessedChange,
        download,
        version_descriptor_version,
        version_descriptor_version_options,
        version_descriptor_version_type,
        include_content,
        resolve_lfs,
        sanitize,
    ):
        url = "https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository_id}/items".format(
            organization=organization, project=project, repository_id=repository_id
        )
        params = {"api-version": self.API_VERSION}
        params["path"] = path_file
        params["scopePath"] = scope_path
        params["recursionLevel"] = recursion_level
        params["includeContentMetadata"] = includeContentMetadata
        params["latestProcessedChange"] = latestProcessedChange
        params["download"] = download
        params["versionDescriptor.version"] = version_descriptor_version
        params["versionDescriptor.versionOptions"] = version_descriptor_version_options
        params["versionDescriptor.versionType"] = version_descriptor_version_type
        params["includeContent"] = include_content
        params["resolveLfs"] = resolve_lfs
        params["sanitize"] = sanitize
        return [url, params]

    def get_source_item(self):
        auth = self.set_auth_basic(self.user, self.token)
        headers = self.set_headers()
        [url, params] = self.get_item()
        return self.send_get_request(url, headers, params, auth)
