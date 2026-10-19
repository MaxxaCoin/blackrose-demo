$root = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/src'
$patterns = @(
 'improve_tool|propose_change|apply_change|revert_change',
 'team_create|team_invite|team_spawn|team_task|team_run|team_broadcast',
 'timeline_view|session_log',
 'image_generate',
 'doc_generate|pptx_create',
 'xlsx_write|xlsx_update|xlsx_pivot',
 'repo_index|repo_map|repo_semantic_search',
 'policy_set|policy_status',
 'audit_query',
 'PLUGIN_LOAD|plugin_load|hot_load',
 'identity_set|identity_get|ai_constitution',
 'video_generate|video_clip',
 'review_diff|review_pr',
 'deploy_config|deploy_run',
 'android_scrape'
)
foreach ($pat in $patterns) {
  Write-Output ("PATTERN: " + $pat)
  Get-ChildItem $root -Recurse -Filter '*.ts' | Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.Name -notmatch '\.test\.' } | ForEach-Object {
    $raw = Get-Content $_.FullName -Raw
    if ($raw -match $pat) {
      Write-Output ("  " + $_.FullName.Replace($root,'') )
    }
  }
}
