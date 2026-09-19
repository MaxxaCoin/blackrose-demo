$body = @{
    client_name = 'Cline-BlackRose'
    grant_types = @('urn:ietf:params:oauth:grant-type:device_code','refresh_token')
    token_endpoint_auth_method = 'none'
} | ConvertTo-Json

try {
    $resp = Invoke-RestMethod -Uri 'https://mcp.motion.so/oauth/register' -Method Post -Body $body -ContentType 'application/json'
    $resp | ConvertTo-Json -Depth 10
} catch {
    Write-Output "STATUS: $($_.Exception.Response.StatusCode.Value__)"
    Write-Output $_.ErrorDetails.Message
}
