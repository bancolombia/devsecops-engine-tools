export interface IConfigTool {
  BANNER: string;
  SECRET_MANAGER: ISecretManager;
  VULNERABILITY_MANAGER: IVulnerabilityManager;
  METRICS_MANAGER: IMetricsManager;
  ENGINE_IAC: IEngine;
  ENGINE_CONTAINER: IEngine;
  ENGINE_DAST: IEngine;
  ENGINE_SECRET: IEngine;
  ENGINE_DEPENDENCIES: IEngine;
}

export interface IEngineList {
  ENGINE_NAME: string;
  TOOLS: string[];
}

export interface IEngine {
  ENABLED: string;
  TOOL: string;
}

export interface IMetricsManager {
  AWS: IMetricsManagerAws;
}

export interface IMetricsManagerAws {
  BUCKET: string;
  ROLE_ARN: string;
  REGION_NAME: string;
}

export interface ISecretManager {
  AWS: ISecretManagerAws;
}

export interface ISecretManagerAws {
  SECRET_NAME: string;
  ROLE_ARN: string;
  REGION_NAME: string;
}

export interface IVulnerabilityManager {
  BRANCH_FILTER: string;
  DEFECT_DOJO: IDefectDojo;
}

export interface IDefectDojo {
  CMDB_MAPPING_PATH: string;
  HOST_CMDB: string;
  HOST_DEFECT_DOJO: string;
  REGEX_EXPRESSION_CMDB: string;
  LIMITS_QUERY: number;
}

export interface IConfigToolEngineList
  extends Omit<
    IConfigTool,
    | TEngines
  > {
  ENGINE_LIST?: IEngineList[];
}

export interface IConfigToolEngineForm
  extends Omit<
    IConfigTool,
    | TEngines
  > {
  ENGINE_IAC: string;
  ENGINE_CONTAINER: string;
  ENGINE_DAST: string;
  ENGINE_SECRET: string;
  ENGINE_DEPENDENCIES: string;
}

export type TEngines =
  | 'ENGINE_IAC'
  | 'ENGINE_CONTAINER'
  | 'ENGINE_DAST'
  | 'ENGINE_SECRET'
  | 'ENGINE_DEPENDENCIES';
