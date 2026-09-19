$clientId = '817fd6d1-8844-40fc-8290-abf6a18737a4'
$deviceCode = 'eChKPp_eYr92amx8Vj-tgIesT0TIhPiRXqlSwB5VhtY'
$interval = 5
$maxTries = 180  # ~15 minutes at 5s interval
$tokenUrl = 'https://mcp.motion.so/oauth/token'

for ($i = 0; $i -lt $maxTries; $i++) {
    Start-Sleep -Seconds $interval
    $body = @{
        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        device_code = $deviceCode
        client_id = $clientId
    }
    try {
        $resp = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
        $resp | ConvertTo-Json -Depth 10 | Out-File -FilePath C:/Users/pc/Desktop/BlackRose/motion_token.json -Encoding utf8
        Write-Output "SUCCESS"
        $resp | ConvertTo-Json -Depth 10
        exit 0
    } catch {
        $errBody = $_.ErrorDetails.Message
        if ($errBody -match 'authorization_pending') {
            Write-Output "pending... ($i)"
            continue
        } elseif ($errBody -match 'slow_down') {
            $interval += 5
            Write-Output "slow_down, new interval $interval"
            continue
        } else {
            Write-Output "ERROR: $errBody"
            exit 1
        }
    }
}
Write-Output "TIMEOUT"
exit 2
