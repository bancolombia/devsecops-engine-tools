export type AiAction =
    | 'fix_with_copilot'
    | 'explain_with_copilot'
    | 'generate_dependency_update'
    | 'generate_image_update';

export type AiTriggerOrigin = 'webview' | 'code_action' | 'tree_context_menu';

export interface IAiMetricsData {
    action: AiAction;
    source_type: string;
    finding_priority: string;
    finding_tool: string;
    trigger_origin: AiTriggerOrigin;
    action_date: string;
}
