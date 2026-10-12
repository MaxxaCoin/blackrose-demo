@echo off
cd /d C:\Users\pc\Desktop\BlackRose\validation\scratch
node C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\index.ts "You are being validated by your developer. Create a file named hello_blackrose.txt in the current directory containing exactly the text BLACKROSE_LIVE_OK, then confirm what you did."
exit /b %ERRORLEVEL%
