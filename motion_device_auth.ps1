$clientId = '817fd6d1-8844-40fc-8290-abf6a18737a4'
$body = @{
    client_id = $clientId
    scope = 'openid email mcp motion:sessions:read motion:sessions:write motion:account:read motion:account:manage motion:credits:read'
}

try {
    $resp = Invoke-RestMethod -Uri 'https://mcp.motion.so/oauth/device_authorization' -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
    $resp | ConvertTo-Json -Depth 10
    $resp | ConvertTo-Json -Depth 10 | Out-File -FilePath C:/Users/pc/Desktop/BlackRose/motion_device_resp.json -Encoding utf8
} catch {
    Write-Output "STATUS: $($_.Exception.Response.StatusCode.Value__)"
    Write-Output $_.ErrorDetails.Message
}
