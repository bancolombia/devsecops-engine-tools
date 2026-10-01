from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.cross_approval_gateway import (
    CrossApprovalGateway,
)


class GetCrossApprovalExclusions:
    def __init__(self, cross_approval_gateway: CrossApprovalGateway):
        self.cross_approval_gateway = cross_approval_gateway

    def execute(self, remote_config, dict_args, secret_tool):
        config = remote_config.get("CROSS_APPROVAL_EXCLUSIONS", {})
        if not config.get("ENABLED", False):
            return []

        url = config.get("URL")
        if not url:
            raise ValueError(
                "CROSS_APPROVAL_EXCLUSIONS is enabled but URL is not configured"
            )

        secret_tool = secret_tool or {}
        token = dict_args.get("token_vulnerability_management") or secret_tool.get(
            "token_defect_dojo"
        )
        if not token:
            raise ValueError(
                "CROSS_APPROVAL_EXCLUSIONS is enabled but Defect Dojo token is missing"
            )

        exclusions = self.cross_approval_gateway.get_approved_exclusions(url, token)
        return [
            Exclusions(
                id=exclusion.id or exclusion.cve_id,
                where=exclusion.where or "all",
                cve_id=exclusion.cve_id,
                create_date=exclusion.create_date,
                expired_date=exclusion.expired_date,
                severity=exclusion.severity,
                priority=exclusion.priority,
                hu=exclusion.hu,
                reason=exclusion.reason or "Defect Dojo cross-approval",
                **{"x86.image.name": exclusion.component.values},
            )
            for exclusion in exclusions
            if exclusion.component.type.lower() == "image"
            and exclusion.component.values
        ]