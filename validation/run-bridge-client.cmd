@echo off
cd /d C:\Users\pc\Desktop\BlackRose\validation\scratch
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts --remote http://127.0.0.1:8787 --token blackrose-val-token-7381 --health >> C:\Users\pc\Desktop\BlackRose\validation\bridge-health.out 2>&1
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts --remote http://127.0.0.1:8787 --token blackrose-val-token-7381 --ask "Reply with exactly this single word and nothing else: BRIDGE_OK" >> C:\Users\pc\Desktop\BlackRose\validation\bridge-ask.out 2>&1
exit /b %ERRORLEVEL%
