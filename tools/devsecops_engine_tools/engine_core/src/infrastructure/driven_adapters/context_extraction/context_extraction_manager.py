from typing import Optional, Dict, Any, List
from dataclasses import asdict
import json
from devsecops_engine_tools.engine_core.src.domain.model.gateway.context_extraction_gateway import (
    ContextExtractionGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.risk_score_gateway import (
    RiskScoreGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class ContextExtractionManager(ContextExtractionGateway):
 
    def __init__(self, risk_score_gateway: RiskScoreGateway):
        self._tool_gateways = {}
        self._risk_score_gateway = risk_score_gateway
        
        # Mapping of module names to their tool gateway method names
        self._method_mapping = {
            "engine_iac": "get_iac_context_from_results",
            "engine_container": "get_container_context_from_results",
            "engine_dependencies": "get_dependencies_context_from_results",
            "engine_license": "get_license_context_from_results",
        }
        
        # Mapping of module names to their context output keys
        self._context_key_mapping = {
            "engine_iac": "iac_context",
            "engine_container": "container_context",
            "engine_dependencies": "dependencies_context",
            "engine_license": "license_context",
        }
        
    def register_tool_gateway(self, module_name: str, tool_gateway: any):
        self._tool_gateways[module_name] = tool_gateway
        logger.info(f"Registered tool gateway for context extraction: {module_name}")
        
    def extract_context(
        self,
        module_name: str,
        path_file_results: Optional[str],
        remote_config: Dict[str, Any],
        config_tool: Dict[str, Any],
        **kwargs
    ) -> None:
        if not path_file_results:
            logger.warning(f"No results file provided for {module_name}, skipping context extraction")
            return
            
        tool_gateway = self._tool_gateways.get(module_name)
        if not tool_gateway:
            logger.warning(f"No tool gateway registered for module: {module_name}")
            return
        
        method_name = self._method_mapping.get(module_name)
        if not method_name:
            logger.warning(f"No context extraction method defined for module: {module_name}")
            return
            
        try:
            logger.info(f"Extracting context for {module_name} from {path_file_results}")
            
            # Get the method from the tool gateway
            method = getattr(tool_gateway, method_name, None)
            if not method:
                logger.error(f"Tool gateway for {module_name} does not implement {method_name}")
                return
            
            # Call the appropriate method to get context list
            context_list: List = []
            if module_name == "engine_dependencies":
                # Dependencies requires remote_config
                context_list = method(path_file_results, remote_config=remote_config, **kwargs)
            else:
                # IaC, Container, and License only need path_file_results
                context_list = method(path_file_results)
            
            if not context_list:
                logger.info(f"No context findings extracted for {module_name}")
                return
            
            # Calculate priority for each context finding
            self._calculate_priorities_for_context(context_list, config_tool, module_name)
            
            # Print context with priorities
            self._print_context(module_name, context_list)
            
            logger.info(f"Context extraction completed for {module_name} with {len(context_list)} findings")
        except FileNotFoundError as e:
            logger.error(f"Results file not found for {module_name}: {path_file_results}")
        except ValueError as e:
            logger.error(f"Invalid results format for {module_name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error extracting context for {module_name}: {str(e)}")
    
    def _calculate_priorities_for_context(
        self,
        context_list: List,
        config_tool: Dict[str, Any],
        module_name: str
    ) -> None:
        # Convert context objects to Finding objects for priority calculation
        findings_for_priority = []
        for context_item in context_list:
            # Extract the ID depending on the context type
            if hasattr(context_item, 'cve_id'):
                if isinstance(context_item.cve_id, list):
                    # For dependencies: cve_id is a list
                    finding_id = context_item.cve_id[0] if context_item.cve_id else "unknown"
                else:
                    # For container: cve_id is a string
                    finding_id = context_item.cve_id
            elif hasattr(context_item, 'id'):
                # For IaC: id is a string
                finding_id = context_item.id
            elif hasattr(context_item, 'name'):
                # For license: name is the identifier
                finding_id = context_item.name
            else:
                finding_id = "unknown"
            
            finding = Finding(
                id=finding_id,
                cvss="",
                where="",
                description="",
                severity=context_item.severity,
                identification_date="",
                published_date_cve="",
                module=module_name,
                category=Category.VULNERABILITY,
                requirements="",
                tool="",
            )
            findings_for_priority.append(finding)
        
        # Calculate priorities using the risk_score_gateway
        self._risk_score_gateway.get_risk_score(findings_for_priority, config_tool, module_name)
        
        # Update context objects with calculated priorities
        # Store only the scale as a string for all modules
        for context_item, finding in zip(context_list, findings_for_priority):
            if finding.priority:
                context_item.priority = finding.priority.scale
    
    def _print_context(self, module_name: str, context_list: List) -> None:
        context_key = self._context_key_mapping.get(module_name, f"{module_name}_context")
        
        print("===== BEGIN CONTEXT OUTPUT =====")
        print(
            json.dumps(
                {
                    context_key: [
                        asdict(context) for context in context_list
                    ]
                },
                indent=2,
            )
        )
        print("===== END CONTEXT OUTPUT =====")
