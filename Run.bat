REM  --> Check for permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
echo off
title AIO WINDOWS TOOL
color0
cls
echo Waiting 5 seconds to start.....
timeout 5
cls
echo These scripts are not made by me i just compiled to a tool.
echo This script tweaks and activates your windows (only for windows 7+) press any key to continue.
echo Update 1.1!
echo Special Thanks:
echo Thanks to UnLovedCookie for tweaker
echo Thanks to kkkgo for kms. 
echo Thanks to YasserDRIF for Toggle Tweaker
echo Thanks to OgnitorenKs for Toolbox :)

timeout 999
:ask
echo 1) Activate Windows
echo 2) Tweak Your Windows
echo 3) Open Toggle Tweaker (ONLY FOR WINDOWS 10!)
echo 4) Install OgnitorenKs Toolbox (Theres a one language and its turkish)
echo 5) Exit
echo Thanks for using my Tool have a nice day :).
set /p choix=What do you want? (1/2/3):
 
if /I "%choix%"=="1" (goto :Activate)
if /I "%choix%"=="2" (goto :Tweak)
if /I "%choix%"=="3" (goto :ToggleTweaker)
if /I "%choix%"=="4" (goto :OgnitorenksToolbox)
if /I "%choix%"=="5" exit
goto ask

:Activate
cls
echo Activating......
start Activator.cmd
echo If you setted up the activator press any key to go next step.
timeout 999
cls
start AutoReneval.cmd
echo If finished the Auto Reneval setup press any key to go main menu.
timeout 999
cls
goto ask

:Tweak
cls
echo Tweaking......
start EchoX.bat
echo If the Tweaker finished the tweaking press any key to go main menu.
timeout 999
cls
goto ask

:ToggleTweaker
cls
echo Starting Toggle Tweaker(only for windows 10)......
start ToggleTweaker.bat
echo If the Tweaker finished the tweaking press any key to go main menu.
timeout 999
cls
goto ask

:OgnitorenKsToolbox
echo Installing OgnitorenKs Toolbox......
start OgnitorenKs.Toolbox.Setup.bat
echo If the Installer finished press any key to go main menu.
timeout 999
cls
goto ask
