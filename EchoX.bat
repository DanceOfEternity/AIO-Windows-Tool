::https://tinyurl.com/echolicence
@echo off
Mode 52,16
title EchoX
set Version=8.6
set DevBuild=No
cd %temp%

::Dark Mode
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v DarkMode 2^>nul') do set "DarkMode=%%a"
if "%DarkMode%" equ "0x1" (
::Text Color Red
set col1=[91m
::Highlight Color Blue
set col2=[94m
color fc
) else (
::Text Color White
set col1=[97m
::Highlight Color Red
set col2=[31m
color f
)

::Enable Delayed Expansion
setlocal EnableDelayedExpansion

::Begin Log
echo Begin Log >%temp%\EchoLog.txt
echo Begin Error Log >%temp%\EchoError.txt

::Choice Prompt Setup
for /f %%A in ('"prompt $H &echo on &for %%B in (1) do rem"') do set BS=%%A

::Enable ANSI escape sequences
Reg add HKCU\CONSOLE /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

::Check For PowerShell
if not exist "%windir%\system32\WindowsPowerShell\v1.0\powershell.exe" (
call:EchoXLogo
echo.
echo %BS%               Missing PowerShell 1.0
echo %BS%             press C to continue anyway
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
)

::Get Admin Rights
if exist "%SystemDrive%\Windows\system32\adminrightstest" (rmdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1)
mkdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1
if %errorlevel% neq 0 (
call:EchoXLogo
echo              %col2%Run EchoX as Admin%col1%
start "" /wait /I /min powershell -NoProfile -NonInteractive -Command start -verb runas "'%~s0'"
exit /b
)

::Check For Internet
Ping www.google.nl -n 1 -w 1000 >nul
if %errorlevel% neq 0 (
call:EchoXLogo
echo.
echo %BS%               No Internet Connection
echo %BS%             press C to continue anyway
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
)

::Run CMD in 32-Bit
set SystemPath=%SystemRoot%\System32
if not "%ProgramFiles(x86)%"=="" (if exist %SystemRoot%\Sysnative\* set SystemPath=%SystemRoot%\Sysnative)
if "%processor_architecture%" neq "AMD64" (start "" /I "%SystemPath%\cmd.exe" /c "%~s0" & exit /b)

::Check For Updates
curl -g -k -L -# -o "%temp%\latestVersion.bat" "https://raw.githubusercontent.com/UnLovedCookie/EchoX/main/Files/Version" >nul 2>&1
call "%temp%\latestVersion.bat"
if "%DevBuild%" neq "Yes" if "%Version%" lss "!latestVersion!" (cls
	call:EchoXLogo
	echo.
	echo             Warning, EchoX isn't updated.
	echo        Would you like to update to version %col2%!latestVersion!?
	echo.
	choice /c:"YN" /n /m "%BS%                   [Y] Yes  [N] No"
	if !errorlevel! equ 1 (
		curl -L -o "%0" "https://github.com/UnLovedCookie/EchoX/releases/latest/download/EchoX.bat" >nul 2>&1
		call %0
		exit /b
	)
)

::Settings
call:EchoXLogo
echo            %col2%Loading Settings [...]%col1%

::Nvidia Driver
set cdCache=%cd%
cd "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI\" >nul 2>&1
for /f "tokens=1" %%a in ('nvidia-smi --query-gpu^=driver_version --format^=csv 2^>nul') do set NvidiaDriverVersion=%%a
cd %cdCache%

if not exist "%SystemRoot%\System32\wbem\WMIC.exe" (
::WMI Settings
Reg add "HKCU\Software\Echo" /f >nul 2>&1
powershell -ExecutionPolicy Unrestricted -NoProfile import-module Microsoft.PowerShell.Management;import-module Microsoft.PowerShell.Utility;^
$GPU = Get-WmiObject win32_VideoController ^| Select-Object -ExpandProperty Name;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "GPU_NAME" -Type String -Value "$GPU";^
$mem = Get-WmiObject win32_operatingsystem ^| Select-Object -ExpandProperty TotalVisibleMemorySize;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "mem" -Type String -Value "$mem";^
$ChassisTypes = Get-WmiObject win32_SystemEnclosure ^| Select-Object -ExpandProperty ChassisTypes;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "ChassisTypes" -Type String -Value "$ChassisTypes";^
$Degrees = Get-WmiObject -Namespace "root/wmi" MSAcpi_ThermalZoneTemperature ^| Select-Object -ExpandProperty CurrentTemperature;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "Degrees" -Type String -Value "$Degrees";^
$CORES = Get-WmiObject win32_processor ^| Select-Object -ExpandProperty NumberOfCores;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "CORES" -Type String -Value "$CORES";^
$osarchitecture = Get-WmiObject win32_operatingsystem ^| Select-Object -ExpandProperty osarchitecture;Set-ItemProperty -Path "HKCU:\Software\Echo" -Name "osarchitecture" -Type String -Value "$osarchitecture"
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v CORES') do set CORES=%%a
for /f "tokens=*" %%a in ('Reg query "HKCU\Software\Echo" /v GPU_NAME') do set GPU_NAME=%%a
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v mem') do set mem=%%a
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v ChassisTypes') do set ChassisTypes=%%a
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Degrees') do set Degrees=%%a
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v osarchitecture') do set osarchitecture=%%a
) >nul 2>&1 else (
::Faster WMIC Settings
rem for /f "tokens=2 delims==" %%n in ('wmic /namespace:\\root\wmi path MSAcpi_ThermalZoneTemperature get CurrentTemperature /value') do set Degrees=%%n
rem for /f "delims=" %%n in ('"wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /format:value"') do set "%%n" >nul 2>&1
for /f "tokens=2 delims==" %%n in ('wmic os get TotalVisibleMemorySize /format:value') do set ram=%%n
for /f "tokens=2 delims==" %%n in ('wmic path Win32_VideoController get Name /format:value') do set GPU_NAME=%%n
for /f "tokens=2 delims==" %%n in ('wmic cpu get numberOfCores /format:value') do set CORES=%%n
for /f "tokens=2 delims={}" %%n in ('wmic path Win32_SystemEnclosure get ChassisTypes /format:value') do set /a ChassisTypes=%%n
) >nul 2>&1

::NSudo
if not exist "%temp%\NSudo.exe" (
echo            Downloading NSudo [...]
curl -g -k -L -# -o "%temp%\NSudo.exe" "https://github.com/UnLovedCookie/EchoX/raw/main/Files/NSudo.exe" >nul 2>&1
)

::Setup Nsudo
Start "" /wait "%temp%\NSudo.exe" -U:S -ShowWindowMode:Hide cmd /c "Reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t REG_DWORD /d "3" /f"
Start "" /wait "%temp%\NSudo.exe" -U:S -ShowWindowMode:Hide cmd /c "sc start "TrustedInstaller"

::Extra Settings
set DualBoot=Unknown
set storageType=Unknown
set CPU_NAME=%PROCESSOR_IDENTIFIER%
set THREADS=%NUMBER_OF_PROCESSORS%

::Nvidia Drivers
if 1 neq 1 if "%NvidiaDriverVersion%" neq "457.30" (
call:EchoXLogo
echo.
echo        Recommended graphics driver not found:
choice /c:12 /n /m "%BS%               [1] Install  [2] Skip"
if !errorlevel!==1 (cls
echo Downloading Nvidia Driver [...]
if exist "%temp%\457.30x64Desktop.exe" del "%temp%\457.30x64Desktop.exe"
Reg query "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DCHUVen" >nul 2>&1
if !errorlevel! equ 0 (set "DL=https://onedrive.live.com/download?cid=91FD8D99AB112B7E&resid=91FD8D99AB112B7E%%21108&authkey=AHcg0GQ-iB6_-AM") else (set "DL=https://onedrive.live.com/download?cid=91FD8D99AB112B7E&resid=91FD8D99AB112B7E%%21106&authkey=AOw9OffeXfkCw8w")
powershell "wget '!DL!' -OutFile '%temp%\457.30x64Desktop.exe'" >nul 2>&1
echo Installing Nvidia Driver [...]
"%temp%\457.30x64Desktop.exe"
if !errorlevel! neq 0 (cls & echo Failed to install Nvidia Drivers [...] & echo You'll have to manually install Nvidia Driver 457.30) else (cls & echo Installed Nvidia Drivers [...])
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
)
)

::Ask about Restore Points
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Restore') do set Restore=%%a) >nul 2>&1
if "%Restore%" equ "" (cls
call:EchoXLogo
echo.
echo           Let EchoX create a Restore Point
echo              (Used to undo all changes^)
choice /c:NY /n /m "%BS%                  [Y] Yes  [N] No"
Reg add "HKCU\Software\Echo" /v Restore /t REG_DWORD /d "!errorlevel!" /f >nul
)

::Check For 64-Bit
if "%PROCESSOR_ARCHITECTURE%" equ "x86" (cls
call:EchoXLogo
echo.
echo %BS%                64-bit Not Detected
echo %BS%          press any key to continue anyway
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
)

::Auto Detect Settings
if defined ChassisTypes if %ChassisTypes% GEQ 8 if %ChassisTypes% LSS 12 (
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Throttling 2^>nul') do set "Throttling=%%a"
if "!Throttling!" equ "" Reg add "HKCU\Software\Echo" /v Throttling /t REG_DWORD /d "1" /f >nul
) else (
for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v PowMax 2^>nul') do set "PowMax=%%a"
if "!PowMax!" equ "" Reg add "HKCU\Software\Echo" /v PowMax /t REG_DWORD /d "1" /f >nul
)

for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v NVCP 2^>nul') do set "NVCP=%%a"
for %%a in (391.35 425.31 441.XX 461.72 456.71 457.30 461.72 461.92 466.11) do (
if not defined NVCP if "%NvidiaDriverVersion%" equ "%%a" Reg add "HKCU\Software\Echo" /v NVCP /t REG_DWORD /d "1" /f >nul
)

rem start "EchoX" /I cmd /c "@echo off & Mode 52,16 & color fc & powershell wget http://optimize.mygamesonline.org/database -OutFile C:\windows\system32\database && call ^"%~s0^" && exit /b 0"
:Home
Mode 52,16
cls
call:EchoXLogo
echo           %col1%[%col2%1%col1%] Optimize  [%col2%2%col1%] More
echo                 [%col2%3%col1%] Undo  [%col2%4%col1%] Credits%col2%
echo.
choice /c:1234 /n /m "%BS%                                  >:"
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto Optimize
if "%MenuItem%"=="2" set "SettingsPage=1" & goto Settings
if "%MenuItem%"=="3" goto Undo
if "%MenuItem%"=="4" goto Credits

:Settings
set SettingsItem=Undefined

cls
if "%SettingsPage%"=="1" (
for %%i in (PowMax Idle Throttling NVCP) do set %%i=[91moff & for /f "tokens=3 skip=2" %%a in ('Reg query HKCU\Software\Echo /v %%i 2^>nul') do if "%%a"=="0x1" set %%i=[32mon
echo.
echo                                          %col2%Page 1/3
echo  %col1%[%col2%1%col1%] Maximum Power Plan !PowMax!
echo  [90mIncreases performance and CPU temperature
echo.
echo  %col1%[%col2%2%col1%] Power-Throttling !Throttling!
echo  [90mDecreases tempurature and performance
echo.
echo  %col1%[%col2%3%col1%] Disable Idle !Idle!
echo  [90mDecreases latency and increases CPU temperature
echo.
echo  %col1%[%col2%4%col1%] NVCP Settings !NVCP!
echo  [90mIncreases performance and GPU temperature%col1%
echo.
choice /c:1234NB /n /m "%BS%                [N] Next   [B] Back"
set /a SettingsItem=!errorlevel!
if "!SettingsItem!"=="5" (set SettingsPage=2)
cls
)

if "%SettingsItem%"=="1" if "%PowMax%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v PowMax /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v PowMax /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="2" if "%Throttling%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v Throttling /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v Throttling /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="3" if "%Idle%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v Idle /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v Idle /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="4" if "%NVCP%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v NVCP /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v NVCP /t REG_DWORD /d "1" /f >nul)
if %SettingsItem% lss 5 goto Settings

if "%SettingsPage%"=="2" (
for %%i in (DarkMode DisplayScaling Restore KBoost) do set %%i=[91moff & for /f "tokens=3 skip=2" %%a in ('Reg query HKCU\Software\Echo /v %%i 2^>nul') do if "%%a"=="0x1" set %%i=[32mon
echo.
echo                                          %col2%Page 2/3
echo  %col1%[%col2%1%col1%] EchoX Light Mode !DarkMode!
echo  [90mRestart EchoX after turning this setting on
echo.
echo  %col1%[%col2%2%col1%] Disable Display Scaling !DisplayScaling!
echo  [90mTurn this on to disable display scaling
echo.
echo  %col1%[%col2%3%col1%] KBoost !KBoost!
echo  [90mIncreases performance and GPU temperature
echo.
echo  %col1%[%col2%4%col1%] Don't Create A Restore Point !Restore!
echo  [90mNot recommended to turn this off%col1%
echo.
choice /c:1234NB /n /m "%BS%                [N] Next   [B] Back"
set SettingsItem=!errorlevel!
if "!SettingsItem!"=="5" (set SettingsPage=4)
cls
)

if "%SettingsItem%"=="1" if "%DarkMode%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v DarkMode /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v DarkMode /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="2" if "%DisplayScaling%"=="[32mon" (Reg add "HKCU\Software\Echo" /v DisplayScaling /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\Software\Echo" /v DisplayScaling /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="3" if "%KBoost%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v KBoost /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v KBoost /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="4" if "%Restore%"=="[32mon" (Reg add "HKCU\SOFTWARE\Echo" /v Restore /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\SOFTWARE\Echo" /v Restore /t REG_DWORD /d "1" /f >nul)
if %SettingsItem% lss 5 goto Settings

if "%SettingsPage%"=="4" (
for %%i in (Res DSCP staticip Mouse) do set %%i=[91moff & for /f "tokens=3 skip=2" %%a in ('Reg query HKCU\Software\Echo /v %%i 2^>nul') do if "%%a"=="0x1" set %%i=[32mon
echo.
echo                                          %col2%Page 3/3
echo  %col1%[%col2%1%col1%] Static IP !staticip!
echo  [90mTurn this on to enable Static IP
echo.
echo  %col1%[%col2%2%col1%] Timer Resolution !Res!
echo  [90mTurn this on for older games
echo.
echo  %col1%[%col2%3%col1%] Mouse Optimization !Mouse!
echo  [90mTurn this off if you use a trackpad
echo.
echo  %col1%[%col2%4%col1%] DSCP Value !DSCP!
echo  [90mTurn this on to prioritize your packets%col1%
echo.
choice /c:1234NB /n /m "%BS%                [N] Next   [B] Back"
set SettingsItem=!errorlevel!
if "!SettingsItem!"=="5" (set SettingsPage=1)
cls
)

if "%SettingsItem%"=="1" if "%staticip%"=="[32mon" (Reg add "HKCU\Software\Echo" /v staticip /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\Software\Echo" /v staticip /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="2" if "%Res%"=="[32mon" (Reg add "HKCU\Software\Echo" /v Res /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\Software\Echo" /v Res /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="3" if "%Mouse%"=="[32mon" (Reg add "HKCU\Software\Echo" /v Mouse /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\Software\Echo" /v Mouse /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="4" if "%DSCP%"=="[32mon" (Reg add "HKCU\Software\Echo" /v DSCP /t REG_DWORD /d "0" /f >nul) else (Reg add "HKCU\Software\Echo" /v DSCP /t REG_DWORD /d "1" /f >nul)
if "%SettingsItem%"=="5" goto Settings
if %SettingsItem% lss 5 goto Settings
goto home

:Optimize
call:GrabSettings

if not "%NVCP%"=="0x1" (
echo Downloading NVCP Settings [...]
if not exist "%temp%\nvidiaProfileInspector.zip" curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip"
if not exist "%temp%\nvidiaProfileInspector" powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath '%temp%\nvidiaProfileInspector\'
curl -g -k -L -# -o "%temp%\nvidiaProfileInspector\EchoProfile.nip" "https://raw.githubusercontent.com/UnLovedCookie/EchoX/main/Files/EchoProfile.nip"
)

if "%Res%"=="0x1" if not exist "%SystemDrive%\EchoRes.exe" (
echo Downloading Timer Resolution [...]
curl -g -k -L -# -o "%SystemDrive%\EchoRes.exe" "https://github.com/UnLovedCookie/EchoX/raw/main/Files/SetTimerResolutionService.exe" >nul 2>&1
)

::Restore Point
if not "%Restore%"=="0x1" (cls
echo Creating System Restore Point [...]
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Echo Optimization' -RestorePointType 'MODIFY_SETTINGS'"
if !errorlevel! neq 0 cls & echo Failed to create a restore point! & echo. & echo Press any key to continue anyway & pause >nul
)

::Registry Backup
if not exist "%SystemDrive%\Regbackup.Reg" (
call:EchoXLogo
echo.
echo %BS%           Creating Registry Backup [...]
Regedit /e "%SystemDrive%\Regbackup.Reg" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
if !errorlevel! neq 0 cls & echo Failed to create a registry backup! & echo. & echo Press any key to continue anyway & pause >nul
)

::BCD Backup
if not exist "%SystemDrive%\bcdbackup.bcd" (
call:EchoXLogo
echo.
echo %BS%           Creating BCD Edit Backup [...]
bcdedit /export "%SystemDrive%\bcdbackup.bcd" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
)

::Fix System Files
rem sfc /scannow
rem Dism /Online /Cleanup-Image /RestoreHealth

::Optimize Drives
rem defrag /C /O

::Powershell
cls
start "" /MIN powershell -NoProfile -NonInteractive -Command $ErrorActionPreference = 'SilentlyContinue';^
Disable-MMAgent -mc -PageCombining;^
Enable-NetAdapterQos -Name "*";^
Disable-NetAdapterPowerManagement -Name "*";^
Get-NetAdapter -IncludeHidden ^| Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled;^
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled -Chimney Disabled;^
Set-NetTCPSetting -SettingName "*" -MemoryPressureProtection Disabled -InitialCongestionWindow 10 >nul 2>&1
echo Disable Page Combining and Memory Compression
echo Disable Network Adapter Power Savings
echo Remove network security mitigations
echo TCPIP Settings

::::::::::::::::::::::
::Win  Optimizations::
::::::::::::::::::::::
title Win Optimizations
echo                  [32mWin Optimizations%col1%

::Animations
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_EXPAND_SZ /d "ነ考" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Animations

::Disable FTH
Reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable FTH

::Disable Desktop Composition
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Desktop Composition

::FSO
Reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disabled FSO

::Auto restart Powershell on error
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::System responsiveness, PanTeR Said to use 14 (20 hexa)
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "20" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo System Responsivness

::Wallpaper quality 100%
Reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Wallpaper Quality

::Slim Windows Defender and SmartScreen (From Melodies Windows 11 Optimizer)
::Start "" /wait "%temp%\NSudo.exe" -U:T -P:E -M:S -ShowWindowMode:Hide cmd /c "sc config WinDefend start=disabled"
::Start "" /wait "%temp%\NSudo.exe" -U:T -P:E -M:S -ShowWindowMode:Hide cmd /c "sc stop WinDefend"
::Start "" /wait "%temp%\NSudo.exe" -U:T -P:E -M:S -ShowWindowMode:Hide cmd /c "sc config WinDefend start=auto"
::Start "" /wait "%temp%\NSudo.exe" -U:T -P:E -M:S -ShowWindowMode:Hide cmd /c "sc start WinDefend"
Reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "6" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "6" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "6" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "6" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Slim Windows Defender and SmartScreen

::Wait time to kill app during shutdown
Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Wait to end service at shutdown
Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Wait to kill non-responding app
Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Speedup app shutdown

::Power Plan
::Import Windows Ultimate PowerPlan
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 88888888-8888-8888-8888-888888888888 >nul 2>&1
powercfg /setactive 88888888-8888-8888-8888-888888888888 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg /delete 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 99999999-9999-9999-9999-999999999999 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg /setactive 99999999-9999-9999-9999-999999999999 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg /delete 88888888-8888-8888-8888-888888888888 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
set EchoXPowName=EchoX
echo Power Plan

::Allow Throttle States: OFF
powercfg /setacvalueindex scheme_current sub_processor THROTTLING 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Device Idle Policy Performance
powercfg -setacvalueindex scheme_current DEVICEIDLE 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Require a password on wakeup: OFF
powercfg -setacvalueindex scheme_current sub_none CONSOLELOCK 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::USB 3 Link Power Management: OFF 
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::USB selective suspend setting: OFF
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Link State Power Management: OFF
powercfg -setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::AHCI Link Power Management - HIPM/DIPM: OFF
powercfg -setacvalueindex scheme_current SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::NVMe Power State Transition Latency Tolerance
powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 1
powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 1

::Interrupt Steering
rem powercfg -setacvalueindex scheme_current SUB_INTSTEER MODE 6 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

if "%Idle%" equ "0x1" (
set EchoXPowName=%EchoXPowName% DIdle
::Disable C-States
powercfg /setacvalueindex scheme_current sub_processor IDLEDISABLE 1 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable C-States
)

if "%PowMax%" equ "0x1" (
set EchoXPowName=%EchoXPowName% MAX
::Enable Legacy P-states
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFINCTHRESHOLD 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFINCPOL 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFDECTHRESHOLD 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFDECPOL 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFCHECK 10 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Legacy P-states
::Use C0
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 20000 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Configure C-States
::Set Turbo Boost To Aggressive At Guaranteed
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 5 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Turbo Boost
::Disable Core Parking
rem powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current SUB_INTSTEER UNPARKTIME 1
powercfg -setacvalueindex scheme_current SUB_INTSTEER PERPROCLOAD 10000
echo Disable Core Parking
::Disable Frequency Scaling
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Frequency Scaling
) else (
::Configure C-States
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 96 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 96 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 20000 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Configure C-States
::Enable Turbo Boost
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Turbo Boost
::Enable Hardware P-states
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUSWINDOW 1000 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Hardware P-States
)

::Apply
powercfg -setactive scheme_current >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
powercfg /changename scheme_current "%EchoXPowName%" "For EchoX Optimizer %Version% (dsc.gg/EchoX) By UnLovedCookie" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

if "%Throttling%"=="0x1" (
::Enable Power Throttling
Reg delete "HKLM\System\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /f >nul 2>&1
Reg delete "HKLM\System\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /f >nul 2>&1
Reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f >nul 2>&1
echo Enable Power Throttling
) else (
::Disable Power Throttling
Reg add "HKLM\System\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Power Throttling
)

::Turn off Inventory Collector
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" d/f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Turn off Windows Error Reporting
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Application Telemetry
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable the Customer Experience Improvement program (Below is 1 to disable)
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Telemetry (Below is 1 to disable)
Reg add "HKLM\Software\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Text/Ink/Handwriting Telemetry
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Telemetry

::Disable Biometrics
Reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Biometrics

::Security/Hardening 
rem Restrict Enumeration of Anonymous SAM Accounts
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220929
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220930
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem Disable NetBIOS, can be exploited and is highly vulnerable. (From Zeta)
sc stop lmhosts >nul 2>&1
sc config lmhosts start=disabled >nul 2>&1
rem NetBios is disabled. If it manages to become enabled, protect against NBT-NS poisoning attacks
Reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "NodeType" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem https://cyware.com/news/what-is-smb-vulnerability-and-how-it-was-exploited-to-launch-the-wannacry-ransomware-attack-c5a97c48
sc stop LanmanWorkstation >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1
rem LanmanWorkstation is disabled. If it manages to become enabled, protect against other attacks
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220932
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem Disable SMB Compression (Possible SMBGhost Vulnerability workaround)
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem Harden lsass
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "AuditLevel" /t REG_DWORD /d "8" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Security/Hardening

::Unneeded Files
del /s /f /q "%SystemDrive%\windows\history\*" >nul 2>&1
del /s /f /q "%SystemDrive%\windows\recent\*" >nul 2>&1
del /s /f /q "%SystemDrive%\windows\spool\printers\*" >nul 2>&1
del /s /f /q "%SystemDrive%\Windows\Prefetch\*" >nul 2>&1
echo Clean Drive

::::::::::::::::::::::
::Remove Mitigations::
::::::::::::::::::::::
cls
title Remove Mitigation
echo                  [32mRemove Mitigations%col1%

::Turn Core Isolation Memory Integrity OFF
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Turn Core Isolation Memory Integrity OFF

::Disable Process Mitigations
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Process Mitigations

::Disable TsX to mitigate ZombieLoad
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f
echo Disable TsX to mitigate ZombieLoad

::Disable Dma Remapping
rem Takes too long, use registry method instead
rem for /f "tokens=1" %%i in ('driverquery') do Reg add "HKLM\System\CurrentControlSet\Services\%%i\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable DmaRemapping

::Disable SEHOP
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable SEHOP

::Disable ASLR
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Disable ASLR

::Disable Spectre And Meltdown
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d "3" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d "3" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
del /f /q "%WinDir%\System32\mcupdate_GenuineIntel.dll" >nul 2>&1
del /f /q "%WinDir%\System32\mcupdate_AuthenticAMD.dll" >nul 2>&1
echo Disable Spectre And Meltdown

::Disable CFG Lock
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable CFG Lock

::Disable NTFS/ReFS and FS Mitigations
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable NTFS/ReFS and FS Mitigations

::Disable System Mitigations
(for /f "tokens=3 skip=2" %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set "mitigation_mask=%%i") >nul 2>&1
for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable System Mitigations

::Pause Maps Updates/Downloads
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Settings Sync
Reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\HKLM\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Advertising Info
Reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Location Tracking
Reg add "HKLM\Software\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem Reg add "HKLM\Software\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Web in Search
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Remote Assistance
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fEnableChatControl" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Windows Settings

::::::::::::::::::::::
::RAM  Optimizations::
::::::::::::::::::::::
cls
title RAM Optimizations
echo                  [32mRAM  Optimizations%col1%


::Storage Optimizations + Ram

::Disallow drivers to get paged into virtual memory
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable Page Combining
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Page Combining

::Set SvcSplitThreshold (revision)
set /a ram=%mem% + 1024000
Reg add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo SvcSplitThreshold

::Use Large System Cache to improve microstuttering
rem Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem echo Enable Large System Cache

if exist "%windir%\System32\fsutil.exe" (
::Raise the limit of paged pool memory
fsutil behavior set memoryusage 2
::https://www.serverbrain.org/solutions-2003/the-mft-zone-can-be-optimized.html
fsutil behavior set mftzone 2
echo Memory Optimizations
::HDD + SSD
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
::https://ttcshelbyville.wordpress.com/2018/12/02/should-you-disable-8dot3-for-performance-and-security/
fsutil behavior set disable8dot3 1
::Disable NTFS compression
fsutil behavior set disablecompression 1
::Disable Last Access information on directories, performance/privacy
if "!storageType!" neq "!storageType:SSD=!" fsutil behavior set disableLastAccess 0
if "!storageType!" neq "!storageType:HDD=!" fsutil behavior set disableLastAccess 1
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo HDD + SSD Optimizations

::Optimize NTFS
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo NTFS Optimizations

::Disabling random drivers verification.
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Disable file paths exceeding 260 characters.
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disk Optimizations

::Pagefile
wmic pagefileset where name="D:\\pagefile.sys" delete >nul 2>&1
wmic pagefileset create name="C:\pagefile.sys" >nul 2>&1
wmic computersystem where name="%computername%" get AutomaticManagedPagefile | find "TRUE" >nul && wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False >nul 2>&1
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=32768,MaximumSize=32768 >nul 2>&1
if %errorlevel% neq 0 wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=16384,MaximumSize=16384 >nul 2>&1
if %errorlevel% neq 0 wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=8192,MaximumSize=8192 >nul 2>&1
if %errorlevel% neq 0 wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=4096,MaximumSize=4096 >nul 2>&1
if %errorlevel% neq 0 wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=2048,MaximumSize=2048 >nul 2>&1
if %errorlevel% neq 0 wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=1024,MaximumSize=1024 >nul 2>&1
if %errorlevel% neq 0 (echo Pagefile Failed) else (echo Pagefile)

::Disable Prefetch
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Prefetch

::Disable Startup Apps
rem del /f /q "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.*" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem echo Disable Start Up Programs

::Background Apps
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Background Apps

::Free unused ram
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Free unused ram

::::::::::::::::::::::
::GPU  Optimizations::
::::::::::::::::::::::
cls
title GPU Optimizations
echo                  [32mGPU  Optimizations%col1%

::Disable Display Scaling Credits to Zusier
if "%DisplayScaling%" equ "0x1" for /f %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /s /f Scaling') do set "str=%%i" & if "!str!" neq "!str:Configuration\=!" (
	Reg add "%%i" /v "Scaling" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
  echo Disable Display Scaling
)

::https://docs.microsoft.com/en-us/windows-hardware/drivers/display/gdi-hardware-acceleration
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableGDIAcceleration" >nul 2>&1
if "%errorlevel%" equ "0" Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableGDIAcceleration" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::Enable Hardware Accelerated Scheduling
reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" >nul 2>&1
if "%errorlevel%" equ "0" Reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Hardware Accelerated Scheduling

::GPU
for /f "tokens=2 delims==" %%a in ('wmic path Win32_VideoController get VideoProcessor /value') do (
	for %%n in (GeForce NVIDIA RTX GTX) do echo %%a | find "%%n" >nul && set "NVIDIAGPU=Found"
	for %%n in (AMD Ryzen) do echo %%a | find "%%n" >nul && set "AMDGPU=Found"
	for %%n in (Intel UHD) do echo %%a | find "%%n" >nul && set "INTELGPU=Found"
)

if "!NVIDIAGPU!" equ "Found" (
::Enable GameMode
Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Echo Enable Gamemode

::Nvidia Reg
Reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Nvidia Reg

::Disable Write Combining
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Write Combining

::Silk Smoothness Option
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Silk Smoothness Option

::Opt out of nvidia telemetry
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Remove Nvidia Telemetry

::Unrestricted Clocks
set cdCache=%cd%
cd "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI\" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
start "" /I /WAIT /B "nvidia-smi" -acp 0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
cd %cdCache%
echo Unrestricted Clocks

::NVCP
if "%NVCP%" equ "0x1" (
start "" /D "%temp%\nvidiaProfileInspector" nvidiaProfileInspector.exe EchoProfile.nip
echo NVCP Settings
)

::OC Scanner Fix, cuz why not?
if not exist "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI" mkdir "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
copy /Y "%windir%\system32\nvml.dll" "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI\nvml.dll" >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo OC Scanner Fix

::Disable GpuEnergyDrv
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable GpuEnergyDrv

::Disable Preemption
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Preemption

::Registry Key For NVIDIA Card
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (

::Disalbe Tiled Display
Reg add "%%a" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disalbe Tiled Display

::Disable TCC
Reg add "%%a" /v "TCCSupported" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable TCC

::Disable HDCP
if exist "C:\Program Files (x86)\Steam\steamapps\common\SteamVR" (
Reg delete "%%a" /v "RMHdcpKeyglobZero" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable HDCP
) else if exist "C:/Program Files/Oculus/Software" (
Reg delete "%%a" /v "RMHdcpKeyglobZero" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable HDCP
) else (
Reg add "%%a" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable HDCP
)

::Force contiguous memory allocation
Reg add "%%a" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Force contiguous memory allocation

::PStates 0 Credits to Timecard & Zusier
rem https://github.com/djdallmann/GamingPCSetup/tree/master/CONTENT/RESEARCH/WINDRIVERS#q-is-there-a-registry-setting-that-can-force-your-display-adapter-to-remain-at-its-highest-performance-state-pstate-p0
if "%pstates%" equ "0x1" (Reg add "%%a" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
if "%pstates%" equ "0x1" (echo PStates 0)

::kboost
if "%KBoost%" equ "0x1" (
Reg add "%%a" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "%%a" /v "PowerMizerLevel" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "%%a" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "%%a" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo KBoost
)
)
)

if "!AMDGPU!" equ "Found" (
::Disable Gamemode
Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >nul
echo Disable Gamemode

::AMD Registry Location
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /s /v "DriverDesc"^| findstr "HKEY AMD ATI"') do if /i "%%i" neq "DriverDesc" (set "REGPATH_AMD=%%i")
::AMD Tweaks
Reg add "%REGPATH_AMD%" /v "3D_Refresh_Rate_Override_DEF" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "3to2Pulldown_NA" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AAF_NA" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "Adaptive De-interlacing" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AllowSkins" /t Reg_SZ /d "false" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AllowSnapshot" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AllowSubscription" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "ASTT_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "AutoColorDepthReduction_NA" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "EnableAspmL1" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "EnableUlps" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "StutterMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "EnableUlps" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "Main3D_DEF" /t Reg_SZ /d "1" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "Main3D" /t Reg_BINARY /d "3100" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "FlipQueueSize" /t Reg_BINARY /d "3100" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "ShaderCache" /t Reg_BINARY /d "3200" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "Tessellation_OPTION" /t Reg_BINARY /d "3200" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "Tessellation" /t Reg_BINARY /d "3100" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "VSyncControl" /t Reg_BINARY /d "3000" /f >nul 2>&1
Reg add "%REGPATH_AMD%\UMD" /v "TFQ" /t Reg_BINARY /d "3200" /f >nul 2>&1
Reg add "%REGPATH_AMD%\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t Reg_BINARY /d "0100000001000000" /f >nul 2>&1

::Melody AMD Tweaks
for %%i in (LTRSnoopL1Latency LTRSnoopL0Latency LTRNoSnoopL1Latency LTRMaxNoSnoopLatency KMD_RpmComputeLatency
        DalUrgentLatencyNs memClockSwitchLatency PP_RTPMComputeF1Latency PP_DGBMMMaxTransitionLatencyUvd
        PP_DGBPMMaxTransitionLatencyGfx DalNBLatencyForUnderFlow DalDramClockChangeLatencyNs
        BGM_LTRSnoopL1Latency BGM_LTRSnoopL0Latency BGM_LTRNoSnoopL1Latency BGM_LTRNoSnoopL0Latency
        BGM_LTRMaxSnoopLatencyValue BGM_LTRMaxNoSnoopLatencyValue) do Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "%%i" /t REG_DWORD /d "1" /f >nul 2>&1
echo Optimized AMD GPU
)

if "!INTELGPU!" equ "Found" (
::Intel iGPU tweaks
for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
    Reg add "%%i" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
    Reg add "%%i" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f
    Reg add "%%i" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f
    Reg add "%%i" /v "DisablePFonDP" /t REG_DWORD /d "1" /f
    Reg add "%%i" /v "EnableCompensationForDVI" /t REG_DWORD /d "1" /f
    Reg add "%%i" /v "NoFastLinkTrainingForeDP" /t REG_DWORD /d "0" /f
    Reg add "%%i" /v "ACPowerPolicyVersion" /t REG_DWORD /d "16898" /f
    Reg add "%%i" /v "DCPowerPolicyVersion" /t REG_DWORD /d "16642" /f
) >nul 2>&1
echo Intel iGPU tweaks

::DedicatedSegmentSize in Intel iGPU
reg query "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" >nul 2>&1
if %ERRORLEVEL% equ 0 (
  Reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1024" /f >nul 2>&1
  echo DedicatedSegmentSize in Intel iGPU
)

echo Optimized INTEL iGPU
)

::::::::::::::::::::::
::CPU  Optimizations::
::::::::::::::::::::::
cls
title CPU Optimizations
echo                  [32mCPU  Optimizations%col1%
::Disable Hibernation + Fast Startup
powercfg /h off >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Hibernation

::Set Win32PrioritySeparation 26 hex/38 dec
Reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Win32PrioritySeparation

::Reliable Timestamp
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "IoPriority" /t REG_DWORD /d "3" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Timestamp Interval

::CPU
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::Fix CPU Stock Speed
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\IntelPPM" /v Start /t REG_DWORD /d 3 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM" /v Start /t REG_DWORD /d 3 /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Fix CPU Stock Speed

::::::::::::::::::::::::
::Latency Optimization::
::::::::::::::::::::::::
cls
title Latency Optimization
echo                 [32mLatency Optimization%col1%

::Disable MMCSS
Reg add "HKLM\System\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
rem extra settings incase MMCSS is reenabled
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "10000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable MMCCSS

::Windows 10+8 
::100%
::Scale 1-to-1
if "%Mouse%" equ "0x1" (
Reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000 /f
Reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000 /f
echo Mouse Acc

rem Missing
echo Windows Scaling
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::DataQueueSize
for /f "tokens=3" %%a in ('Reg query "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" 2^>nul') do set /a "kbdqueuesize=%%a"
if "%kbdqueuesize%" gtr "50" Reg add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "50" /f >nul 2>&1
for /f "tokens=3" %%a in ('Reg query "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" 2^>nul') do set /a "mssqueuesize=%%a"
if "%mssqueuesize%" gtr "50" Reg add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "50" /f >nul 2>&1
echo DataQueueSize

::CSRSS priority
::csrss is responsible for mouse input, setting to high may yield an improvement in input latency.
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d "3" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo CSRSS priority

for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
::Del GPU Device Priority
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::Enable MSI Mode on GPU if supported
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo GPU MSI Mode

::Remove GPU Limits
Reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Remove GPU Limits

::Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% leq 4 if %CORES% neq %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::No Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% leq 4 if %CORES% equ %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "02" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::More than 4 cores Affinites (GPU AllProccessorsInMachine)
if %THREADS% gtr 4 (
Reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "3" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo GPU Affinites
)

for /f %%i in ('wmic path win32_NetworkAdapter get PNPDeviceID') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
::DEL NET Device Priority
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::Enable MSI Mode on Net
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo NET MSI Mode

::Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% lss 4 if %CORES% neq %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "30" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::No Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% lss 4 if %CORES% equ %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::More than 4 cores Affinites (NET SpreadMessageAcrossAllProccessors)
if %THREADS% gtr 4 (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo NET Affinites
)

for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
::DEL Sata controllers Device Priority
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Delete Device Priority on Sata controllers

::Enable MSI Mode on Sata controllers
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable MSI Mode on Sata controllers
)

for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
::DEL USB Device Priority
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::Enable MSI Mode on USB
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo USB MSI Mode

::Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% lss 4 if %CORES% neq %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
::No Hyperthreading 4 Cores
if %THREADS% gtr 2 if %THREADS% lss 4 if %CORES% equ %THREADS% (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "08" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo USB Affinites
)

::Disable USB Power Savings
for /f "tokens=*" %%i in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr "StorPort"') do Reg add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable USB Power Savings

::Disable Power Saving
for /f "tokens=*" %%i in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr "USB\VID_"') do (
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Power Savings

::::::::::::::::::::::
::Bios Optimizations::
::::::::::::::::::::::
cls
title BIOS Optimizations
echo                  [32mBIOS Optimizations%col1%

if "%Res%" equ "0x1" (
::Timer Resolution
%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /i SetTimerResolutionService.exe >nul 2>&1
bcdedit /set disabledynamictick yes >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set useplatformtick yes >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
sc config "STR" start=auto >nul 2>&1
sc start STR >nul 2>&1
echo Timer Resolution
) else (
::Disable HPET
sc config "STR" start=disabled >nul 2>&1
sc stop STR >nul 2>&11
if exist "%temp%\EchoView.exe" ("%temp%\EchoView.exe" /disable "High Precision Event Timer" >nul 2>&1)
bcdedit /deletevalue useplatformclock >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set disabledynamictick yes >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable HPET
)

::Better Input
bcdedit /set tscsyncpolicy legacy >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo tscsyncpolicy legacy

::Quick Boot
if "%duelboot%" equ "yes" (bcdedit /timeout 0) >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set bootuxdisabled On >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set bootmenupolicy Legacy >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set quietboot yes >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Quick Boot

::Disable Hyper-V
bcdedit /set hypervisorlaunchtype off >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Hyper-V

::Disable Early Launch Anti-Malware Protection
bcdedit /set disableelamdrivers Yes >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Early Launch Anti-Malware Protection

::Windows 8 Boot Stuff
for /f "tokens=4-9 delims=. " %%i in ('ver') do set winversion=%%i.%%j
REM windows 8.1
if "!winversion!" == "6.3.9600" (
bcdedit /set {globalsettings} custom:16000067 true >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set {globalsettings} custom:16000069 true >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set {globalsettings} custom:16000068 true >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Windows 8 Boot Stuff
)

::Disable Data Execution Prevention
echo %PROCESSOR_IDENTIFIER% ^| find "Intel" >nul && bcdedit /set nx optout >nul || bcdedit /set nx alwaysoff >nul
echo Disable Data Execution Prevention

::Linear Address 57
bcdedit /set linearaddress57 OptOut >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set increaseuserva 268435328 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Linear Address 57

::Disable some of the kernel memory mitigations
bcdedit /set isolatedcontext No >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set allowedinmemorysettings 0x0 >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Kernel memory mitigations

::Disable DMA memory protection and cores isolation
bcdedit /set vsmlaunchtype Off >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set vm No >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo DMA memory protection and cores isolation

::Enable X2Apic
bcdedit /set x2apicpolicy Enable >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set uselegacyapicmode No >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable X2Apic

::Enable Memory Mapping for PCI-E devices
bcdedit /set configaccesspolicy Default >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set MSI Default >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set usephysicaldestination No >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
bcdedit /set usefirmwarepcisettings No >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable Memory Mapping

::::::::::::::::::::::
::TCPIP Optimization::
::::::::::::::::::::::
cls
title TCPIP Optimization
echo                  [32mTCPIP Optimization%col1%

::Do not use NLA
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"

::Set max port to 65535
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Set max port to 65535

::Reduce TIME_WAIT
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Reduce TIME_WAIT

::Disable Window Scaling Heuristics (tries to identify connectivity and throughput problems and take appropriate measures.) 
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Disable Window Scaling Heuristics

::Enable TCP Extensions for High Performance
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"  
echo Enable TCP Extensions for High Performance

::Detect congestion fail to receive acknowledgement for a packet within the estimated timeout
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Detect congestion fails

::Network Priorities
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Network Priorities

::Enable The Network Adapter Onboard Processor
netsh int ip set global taskoffload=enabled >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Enable The Network Adapter Onboard Processor

::Disable NetBios
Reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /v "NetbiosOptions" /t REG_DWORD /d "2" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable NetBios

::Reduce Time To Live
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Reduce Time To Live

::Duplicate ACKs
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >nul 2>&1
::Disable SACKS
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >nul 2>&1

::Disable IPv6
rem Reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "4294967295" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 

::Disable Nagle's Algorithm
Reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1  
rem https://en.wikipedia.org/wiki/Nagle%27s_algorithm
for /f %%s in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s') do set "str=%%i" & if "!str:ServiceName_=!" neq "!str!" (
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
		Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpInitialRTT" /d "300" /t REG_DWORD /f
        Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "UseZeroBroadcast" /d "0" /t REG_DWORD /f
        Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "DeadGWDetectDefault" /d "1" /t REG_DWORD /f
) >>"%temp%\EchoLog.txt" 2>>nul
echo Disable Nagle's Algorithm

::::::::::::::::::::::
::Net  Optimizations::
::::::::::::::::::::::
cls
title Network Optimizations
echo                  [32mNet Optimizations%col1%

::Lanman Server
rem Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "a" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 

::Set the maximum number of concurrent connections (per server endpoint) allowed when making requests using an HttpClient object.
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
::Maximum number of HTTP 1.0 connections to a Web server
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo Maximum number of concurrent connections

::TCP Congestion Control/Avoidance Algorithm
Reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
Reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt" 
echo TCP Congestion Control/Avoidance Algorithm

::Enable DNS over HTTPS
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f >nul 2>&1
echo Enable DNS over HTTPS

::https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.QualityofService::QosTimerResolution
Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
Reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Qos TimerResolution

::Disable LLMNR
Reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable LLMNR

::Remove OneDrive Sync
Reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Remove OneDrive Sync

::Disable Delivery Optimization
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Disable Delivery Optimization

::Disable limiting bandwith
::https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.QualityofService::QosNonBestEffortLimit
Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Remove Limiting Bandwidth

::Network Throttling Index
::https://cdn.discordapp.com/attachments/890128142075850803/890135598566895666/unknown.png
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Network Throttling Index

::NIC
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do (
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
::Disable Keys w "*"
Reg add "%%g" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*FlowControl" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*EEE" /t REG_SZ /d "0" /f
::Disable Keys wo "*"
Reg add "%%g" /v "EnablePME" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WakeOnLink" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ULPMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "GigaLite" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
::Disable JumboPacket
Reg add "%%g" /v "JumboPacket" /t REG_SZ /d "0" /f
::Interrupt Moderation Adaptive (Default)
Reg add "%%g" /v "ITR" /t REG_SZ /d "125" /f
::Receive/Transmit Buffers
Reg add "%%g" /v "ReceiveBuffers" /t REG_SZ /d "266" /f
Reg add "%%g" /v "TransmitBuffers" /t REG_SZ /d "266" /f
::Disable Wake Features
Reg add "%%g" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
::Disable LargeSendOffloads
Reg add "%%g" /v "LsoV2IPv4" /t REG_SZ /d "0" /f
Reg add "%%g" /v "LsoV2IPv6" /t REG_SZ /d "0" /f
::PnPCapabilities
Reg add "%%g" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
::Disable Offloads
Reg add "%%g" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
Reg add "%%g" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
Reg add "%%g" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PMARPOffload" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PMNSOffload" /t REG_SZ /d "0" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
::RSS
Reg add "%%g" /v "RSS" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*NumRssQueues" /t REG_SZ /d "2" /f
if %CORES% geq 6 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "4" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "5" /f
) else if %CORES% geq 4 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "3" /f
) else (
Reg delete "%%g" /v "*RssBaseProcNumber" /f
Reg delete "%%g" /v "*RssMaxProcNumber" /f
)
) >nul 2>&1
)
echo NIC

::Internet Priority
if "%DSCP%"=="0x1" (
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "Start" /t REG_DWORD /d "1" /f >nul 2>&1
Start "" /wait "%temp%\NSudo.exe" -U:T -P:E -ShowWindowMode:Hide cmd /c sc start Psched
for %%i in (csgo VALORANT-Win64-Shipping javaw FortniteClient-Win64-Shipping ModernWarfare r5apex) do (
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t REG_SZ /d "%%i.exe" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t REG_SZ /d "1.0" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t REG_SZ /d "46" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t REG_SZ /d "-1" /f
) >nul 2>&1
echo Priority
)

::Static IP Credits: Zusier
if "%staticip%" equ "0x1" (
set dns1=1.1.1.1
for /f "tokens=4" %%i in ('netsh int show interface ^| find "Connected"') do set devicename=%%i
::for /f "tokens=2 delims=[]" %%i in ('ping -4 -n 1 %ComputerName%^| findstr [') do set LocalIP=%%i
for /f "tokens=3" %%i in ('netsh int ip show config name^="%devicename%" ^| findstr "IP Address:"') do set LocalIP=%%i
for /f "tokens=3" %%i in ('netsh int ip show config name^="%devicename%" ^| findstr "Default Gateway:"') do set DHCPGateway=%%i
for /f "tokens=2 delims=()" %%i in ('netsh int ip show config name^="Ethernet" ^| findstr "Subnet Prefix:"') do for /F "tokens=2" %%a in ("%%i") do set DHCPSubnetMask=%%a
netsh int ipv4 set address name="%devicename%" static %LocalIP% %DHCPSubnetMask% %DHCPGateway%
powershell -NoProfile -NonInteractive -Command "Set-DnsClientServerAddress -InterfaceAlias "%devicename%" -ServerAddresses %dns1%"
) >>"%temp%\EchoLog.txt" 2>>nul
if "%staticip%" equ "0x1" echo Static IP

::Netsh
netsh int tcp set supplemental template=Internet >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
netsh int tcp set supplemental Internet congestionprovider=bbr2 enablecwndrestart=disable >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
netsh int tcp set security mpp=disabled profiles=disabled >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
netsh int tcp set heur forcews=disable >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
netsh int tcp set global rss=enabled autotuninglevel=normal ecncapability=disable dca=enabled netdma=disabled ^
timestamps=disabled rsc=disabled nonsackrttresiliency=disabled maxsynretransmissions=2 ^
fastopen=enabled fastopenfallback=default hystart=disabled prr=default pacingprofile=off >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
netsh int ip set global groupforwardedfragments=disable icmpredirects=disabled minmtu=576 flowlabel=disable multicastforwarding=disabled >>"%temp%\EchoLog.txt" 2>>"%temp%\EchoError.txt"
echo Netsh

title EchoX
rundll32 user32.dll,MessageBeep
call:EchoXLogo
rem for /f "delims=" %%i in (%temp%\EchoError.txt) do set "EchoError=%%i" & if "%EchoError: =%" neq "BeginErrorLog" (echo %BS%     There was a error while applying Echo...) else (echo %BS%       Optimizations Finished)
echo %BS%       Optimizations Finished
echo %BS%             Restart to fully apply...
echo.
echo.
choice /c:"BQS" /n /m "%BS%       [Q] Quit   [S] Soft-Restart   [B] Back"
if %errorlevel% equ 2 exit /b
if "%errorlevel%"=="3" call:softRestart
goto Home

:gameBooster
cls & echo Select the game location
set dialog="about:<input type=file id=FILE><script>FILE.click();new ActiveXObject
set dialog=%dialog%('Scripting.FileSystemObject').GetStandardStream(1).WriteLine(FILE.value);
set dialog=%dialog%close();resizeTo(0,0);</script>"
for /f "tokens=* delims=" %%p in ('mshta.exe %dialog%') do set "file=%%p"

cls & if "%file%"=="" goto:eof
for %%F in ("%file%") do Reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" >nul 2>&1 && (
	Reg delete "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "%file%" /f >nul 2>&1
	Reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "CpuPriorityClass" /f >nul 2>&1
	echo Undo Game Optimizations
) || (
	Reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "%file%" /t REG_SZ /d "GpuPreference=2;" /f >nul 2>&1
	Reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%file%" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE" /f >nul 2>&1
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~nxF\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul 2>&1
	echo GPU High Performance
	echo Disable Fullscreen Optimizations
	echo CPU High Class
)
echo.
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
goto:eof

:softRestart
cls
cd %temp%

echo Downloading Restart64 [...]
if not exist "%temp%\restart64.exe" curl -g -L -# -o "%temp%\Restart64.exe" "https://github.com/UnLovedCookie/EchoX/raw/main/Files/restart64.exe"
echo Downloading EmptyStandbyList [...]
if not exist "%temp%\EmptyStandbyList.exe" curl -g -L -# -o "%temp%\EmptyStandbyList.exe" "https://wj32.org/wp/download/1455/"
cls

::Restart Explorer
taskkill /f /im explorer.exe >nul 2>&1 && start explorer.exe >nul 2>&1
echo Restart Explorer

::Restart Graphics Driver
echo Restarting Graphics Driver [...]
Restart64.exe

::Refresh Internet
echo Refreshing Internet [...]
::Reset Firewall
echo netsh advfirewall reset >RefreshNet.bat
::Release the current IP address obtains a new one.
echo ipconfig /release >>RefreshNet.bat
echo ipconfig /renew >>RefreshNet.bat
::Delete and reacquire the hostname.
echo arp -d * >>RefreshNet.bat
::Purge and reload the remote cache name table.
echo nbtstat -R >>RefreshNet.bat
::Sends Name Release packets to WINS and then refreshes.
echo nbtstat -RR >>RefreshNet.bat
::Flush the DNS and Begin manual dynamic registration for DNS names and IP addresses.
echo ipconfig /flushdns >>RefreshNet.bat
echo ipconfig /registerdns >>RefreshNet.bat
start "" /wait NSudo.exe -U:T -P:E -M:S -ShowWindowMode:Hide -wait cmd /c "%temp%\RefreshNet.bat"

::Clean Standby List
echo Cleaning Standby List [...]
for %%i in (workingsets modifiedpagelist standbylist priority0standbylist) do EmptyStandbyList %%i
goto:eof

:Undo
cls
echo.
echo How to revert changes:
echo.
echo.
echo 1. Hold shift and press restart
echo 2. Find Command Prompt
echo 3. Type a letter and a hyphen e.g. "C:" or "E:"
echo 4. Type "dir"
echo 5. If Regbackup isnt listed,
echo    Go back to step 3 using another letter
echo 6. Type Regedit.exe /s "Regbackup"
echo 7. Type bcdedit.exe /import "bcdbackup"
echo.
echo.
choice /c:QB /n /m "%BS%                [Q] Quit   [B] Back" & if !errorlevel! equ 1 exit /b
goto :Home

:Credits
cls
echo.
echo %col1%[======================Creator=====================]
echo.
echo                     UnLovedCookie
echo.
echo            Discord Tag: UnLovedCookie#6871
echo.
echo                  EchoX Discord Server
echo        %col2% https://discord.com/invite/dptDHp9p9k %col1%
echo.
echo                     Youtube Channel
echo  %col2% www.youtube.com/channel/UCc8L3DAQ2b9pyD7K9siHl9Q %col1%
echo.
echo [===============================================P1=]
choice /c:"NB" /n /m "%BS%                 [N] Next  [B] Back"
if !errorlevel! neq 1 goto :Home
cls
echo.
echo [======================Credits=====================]
echo.
echo  Zusier - Network + More      mbk1969 - Timer Res 
echo  Melody - Pagefile + Debloat  M2Teams - NSudo
echo  Matishzz - AMD and Device    Orbmu2k - NVInspector
echo.
echo [===================Special=Thanks=================]
echo.
echo  EverythingTech - Helped      Vuk - Tweak
echo  Couleur - App Settings       Waffle - Helped
echo  AuraSide Inc - Debloat       yungkkj - Powerplan
echo.
echo [===============================================P2=]
choice /c:"NB" /n /m "%BS%                 [N] Next  [B] Back"
if !errorlevel! neq 1 goto :Home
goto :Credits

:EchoXLogo
cls
echo.
echo.%col1%
echo %BS%     ______ _____ ___ ___ _______    %col2%___   ___%col1%
echo %BS%    ^|\   __\   ___\  \\  \\   _  \  %col2%^|\  \ /  /^|%col1%
echo %BS%    \ \  \__\  \__^|\  \\  \\  \\  \ %col2%\ \  \  / /%col1%
echo %BS%     \ \   __\  \   \   _  \\  \\  \ %col2%\ \   / /%col1%
echo %BS%      \ \  \__\  \___\  \\  \\  \\  \%col2% \/   \/%col1%
echo %BS%       \ \_____\______\  \\__\\______\%col2%/  \  \%col1%
echo %BS%        \^|_____^|______^|__^|^|__^|^|______%col2%/__/ \__\%col1%
echo %BS%                                     %col2%^[__^|\^|__]%col1% %Version%
goto:eof

::original
echo.
echo.
echo %BS%     ______ _____ ___ ___ _______    ___   ___
echo %BS%    ^|\   __\   ___\  \\  \\   _  \  ^|\  \ /  /^|
echo %BS%    \ \  \__\  \__^|\  \\  \\  \\  \ \ \  \  / /
echo %BS%     \ \   __\  \   \   _  \\  \\  \ \ \   / /
echo %BS%      \ \  \__\  \___\  \\  \\  \\  \ \/   \/
echo %BS%       \ \_____\______\  \\__\\______\/  \  \
echo %BS%        \^|_____^|______^|__^|^|__^|^|______/__/ \__\
echo %BS%                                     [__^|\^|__] %Version%

:GrabSettings
::Power
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v PowMax') do set PowMax=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Throttling') do set Throttling=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Idle') do set Idle=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v NVCP') do set NVCP=%%a) >nul 2>&1
::Advanced
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Debloat') do set Debloat=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v DisplayScaling') do set DisplayScaling=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v KBoost') do set KBoost=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Restore') do set Restore=%%a) >nul 2>&1
::Optional
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v staticip') do set staticip=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Res') do set Res=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v Mouse') do set Mouse=%%a) >nul 2>&1
(for /f "tokens=3 skip=2" %%a in ('Reg query "HKCU\Software\Echo" /v DSCP') do set DSCP=%%a) >nul 2>&1
goto:eof
