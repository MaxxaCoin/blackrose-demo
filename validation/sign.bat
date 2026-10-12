@echo off
title BlackRose 0.9.15 SIGNED BUILD
cd /d "C:\Users\pc\Desktop\BlackRose\cline\blackrose"
powershell -ExecutionPolicy Bypass -NoProfile -File "C:\Users\pc\Desktop\BlackRose\cline\blackrose\scripts\sign-release.ps1"
pause
