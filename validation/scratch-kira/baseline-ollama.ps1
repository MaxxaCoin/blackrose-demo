Write-Output '=== GPU ==='
try { nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>$null } catch { Write-Output 'no nvidia-smi' }
Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
Write-Output '=== OLLAMA MODELS ==='
ollama list 2>$null
Write-Output '=== BASELINE qwen2.5-coder:7b ==='
$sw = [Diagnostics.Stopwatch]::StartNew()
$body = '{"model":"qwen2.5-coder:7b","prompt":"Say OK","stream":false,"options":{"num_predict":16}}'
$r = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/generate' -Method Post -Body $body -UseBasicParsing -TimeoutSec 600
$sw.Stop()
$j = $r.Content | ConvertFrom-Json
Write-Output ('wall_ms=' + $sw.ElapsedMilliseconds + ' prompt_eval_ms=' + [math]::Round($j.prompt_eval_duration/1e6) + ' eval_ms=' + [math]::Round($j.eval_duration/1e6) + ' eval_rate_tps=' + [math]::Round($j.eval_count/($j.eval_duration/1e9),1))
Write-Output 'BASELINE_DONE'
