@echo off
rem Background wrapper: detached scheduler validation run (step c) with an
rem isolated state dir so evidence is self-contained under validation\.
set BLACKROSE_DATA_DIR=C:\Users\pc\Desktop\BlackRose\validation\scratch-validation
cd /d C:\Users\pc\Desktop\BlackRose\validation\scratch
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts > C:\Users\pc\Desktop\BlackRose\validation\c-schedule.live.log 2>&1
