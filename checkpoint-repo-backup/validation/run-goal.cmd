@echo off
cd /d C:\Users\pc\Desktop\BlackRose\validation\scratch
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts --goal "Create a folder named goalcheck containing a file report.txt whose content is the single word DONE, and verify the file exists with that content."
exit /b %ERRORLEVEL%
