import { Finding } from "../Finding";
import { formatImpactPathsCollapsed, formatImpactPathsForPrompt } from "../../../infrastructure/helper/ImpactPathFormatter";
import { ImpactPath } from "../../../infrastructure/helper/ImpactPathFormatter";

export interface IIacContext {
  id: string;
  custom_vuln_id: string;
  check_name: string;
  check_class: string;
  severity: string;
  where: string;
  resource: string;
  references: string[];
  description: string;
  module: string;
  vulnerability_status: string;
  tool: string;
  priority: string;
}

export interface IImageScanContext {
  cve_id: string;
  cwe_id: string;
  vendor_id: string;
  severity: string;
  vulnerability_status: string;
  target_image: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  cvss_score: string;
  cvss_vector: string;
  description: string;
  os_type: string;
  layer_digest: string;
  published_date: string;
  last_modified_date: string;
  references: string[];
  module: string;
  source_tool: string;
  priority: string;
}

export interface IDependenciesScanContext {
  cve_id: string[];
  severity: string;
  component: string;
  package_name: string;
  installed_version: string;
  fixed_version: string[];
  impact_paths: ImpactPath[];
  description: string;
  references: string[];
  source_tool: string;
  priority: string;
}

export interface ISeverityCounts {
  very_critical: string;
  critical: string;
  high: string;
  medium_low: string;
  unknown: string;
}

export class Mappers {
  public static mapIacContextToFinding(
    iacContext: IIacContext
  ): Finding {
    return new Finding(
      iacContext.custom_vuln_id || iacContext.id || "",
      iacContext.severity || "unknown",
      iacContext.priority || "",
      iacContext.where || "",
      iacContext.description || "",
      iacContext.module || "engine_iac",
      iacContext.tool || "",
      iacContext.references || [],
      {
        custom_vuln_id: iacContext.custom_vuln_id || "",
        check_name: iacContext.check_name || "",
        check_class: iacContext.check_class || "",
        resource: iacContext.resource || "",
        vulnerability_status: iacContext.vulnerability_status || "unknown"
      }
    );
  }

  public static mapImageScanContextToFinding(
    imageScanContext: IImageScanContext
  ): Finding {
    return new Finding(
      imageScanContext.cve_id || "",
      imageScanContext.severity || "unknown",
      imageScanContext.priority || "",
      imageScanContext.package_name +
      " " +
      imageScanContext.os_type +
      ":" +
      imageScanContext.layer_digest || "",
      imageScanContext.description || "",
      imageScanContext.module || "engine_container",
      imageScanContext.source_tool || "",
      imageScanContext.references || [],
      {
        cwe_id: imageScanContext.cwe_id || "",
        vendor_id: imageScanContext.vendor_id || "",
        vulnerability_status: imageScanContext.vulnerability_status || "unknown",
        target_image: imageScanContext.target_image || "",
        package_name: imageScanContext.package_name || "",
        installed_version: imageScanContext.installed_version || "",
        fixed_version: imageScanContext.fixed_version || "",
        cvss_score: imageScanContext.cvss_score || "",
        cvss_vector: imageScanContext.cvss_vector || "",
        published_date: imageScanContext.published_date || "",
        last_modified_date: imageScanContext.last_modified_date || "",
        layer_digest: imageScanContext.layer_digest || ""
      }
    );
  }

  public static mapDependenciesScanContextToFinding(
    dependenciesScanContext: IDependenciesScanContext
  ): Finding {
    return new Finding(
      dependenciesScanContext.cve_id.join(",") || "",
      dependenciesScanContext.severity || "unknown",
      dependenciesScanContext.priority || "",
      dependenciesScanContext.component || "",
      dependenciesScanContext.description || "",
      "engine_dependencies",
      dependenciesScanContext.source_tool || "",
      dependenciesScanContext.references || [],
      {
        package_name: dependenciesScanContext.package_name || "",
        installed_version: dependenciesScanContext.installed_version || "",
        fixed_version: dependenciesScanContext.fixed_version.join(",") || "",
        impact_paths: formatImpactPathsCollapsed(dependenciesScanContext.impact_paths),
        impact_paths_prompt: formatImpactPathsForPrompt(dependenciesScanContext.impact_paths)
      }
    );
  }
}
