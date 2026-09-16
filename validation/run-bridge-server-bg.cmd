@echo off
rem Background wrapper: detached bridge-server validation run (step d) with an
rem isolated state dir so the audit log stays under validation\.
set BLACKROSE_DATA_DIR=C:\Users\pc\Desktop\BlackRose\validation\scratch-validation
set BLACKROSE_BRIDGE_TOKEN=blackrose-val-token-7381
cd /d C:\Users\pc\Desktop\BlackRose\validation\scratch
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts --bridge 8787 > C:\Users\pc\Desktop\BlackRose\validation\d-bridge-server.live.log 2>&1
