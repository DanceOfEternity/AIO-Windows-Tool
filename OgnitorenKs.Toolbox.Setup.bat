:: ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
::
::       ██████   ██████   ██    ██ ████ ████████  ██████  ████████  ████████ ██    ██ ██    ██  ██████
::      ██    ██ ██    ██  ███   ██  ██     ██    ██    ██ ██     ██ ██       ███   ██ ██   ██  ██    █
::      ██    ██ ██        ████  ██  ██     ██    ██    ██ ██     ██ ██       ████  ██ ██  ██   ██
::      ██    ██ ██   ████ ██ ██ ██  ██     ██    ██    ██ ████████  ██████   ██ ██ ██ █████      ██████ 
::      ██    ██ ██    ██  ██  ████  ██     ██    ██    ██ ██   ██   ██       ██  ████ ██  ██         ██
::      ██    ██ ██    ██  ██   ███  ██     ██    ██    ██ ██    ██  ██       ██   ███ ██   ██  ██    ██
::       ██████   ██████   ██    ██ ████    ██     ██████  ██     ██ ████████ ██    ██ ██    ██  ██████ 
::
::                    ████████ ███████ ███████ ██      ██████  ███████  ██    ██
::                       ██    ██   ██ ██   ██ ██      ██   ██ ██   ██   ██  ██  
::                       ██    ██   ██ ██   ██ ██      ██████  ██   ██     ██   
::                       ██    ██   ██ ██   ██ ██      ██   ██ ██   ██   ██  ██
::                       ██    ███████ ███████ ███████ ██████  ███████  ██    ██
::
::  ► Hazırlayan: Hüseyin UZUNYAYLA / OgnitorenKs
::
::  ► İletişim - Contact;
::  --------------------------------------
::  • Discord: OgnitorenKs#2737 
::  •    Mail: ognitorenks@gmail.com
::  •    Site: https://ognitorenks.blogspot.com/
::
:: ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
echo off
cls
chcp 65001 > NUL 2>&1
mode con cols=80 lines=30
title OgnitorenKs Toolbox Katılımsız Yükleyici

setlocal
Call :ColorEnd

:: Konum bilgisi alınır.
cd /d "%~dp0"
for /f %%a in ('"cd"') do set Location=%%a

:: İnternet bağlantı durumu kontrol edilir.
:netkonroll
ping -n 1 www.bing.com -w 20000 > NUL
	if %errorlevel%==1 (Call :netkontrol&goto exit)
	
:: Eski toolbox kalıntıları silinir.
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\OgnitorenKs.Toolbox.bat" > NUL 2>&1
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Files\Toolbox.zip" > NUL 2>&1
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Files\oscdimg.exe" > NUL 2>&1
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Files\NSudo.exe" > NUL 2>&1
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Files\lnk.zip" > NUL 2>&1
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Files\.wget-hsts" > NUL 2>&1
RD /S /Q "C:\OgnitorenKs.Toolbox\Files\ico" > NUL 2>&1
RD /S /Q "C:\OgnitorenKs.Toolbox\Extra" > NUL 2>&1
RD /S /Q "C:\OgnitorenKs.Toolbox\Edit" > NUL 2>&1
RD /S /Q "C:\OgnitorenKs.Toolbox\Download" > NUL 2>&1
	
:: wget.exe dosyası kontrol edilir.	
dir /b C:\OgnitorenKs.Toolbox\Files\wget.exe > NUL 2>&1
	if %errorlevel%==1 (Call :wget)	

:: C diski içinde OgnitorenKs.Toolbox klasörü açılır
mkdir C:\OgnitorenKs.Toolbox > NUL 2>&1
Call :bosluk
echo                       %R%[92m OgnitorenKs Toolbox Yükleniyor...%R%[0m
echo.            
echo               [■■■■■■■■■■■■                                    ]
Call :ogni
:: OgnitorenKs.Toolbox dosyaları indirilir.
C:\OgnitorenKs.Toolbox\Files\wget --no-check-certificate "https://docs.google.com/uc?export=download&id=1g8mbmzrFcXSZT7r5Oiwdqfs9wGNS2xWl" -O C:\OgnitorenKs.Toolbox\OgnitorenKs.Toolbox.zip > NUL 2>&1
cls
Call :bosluk
echo                       %R%[92m OgnitorenKs Toolbox Yükleniyor...%R%[0m
echo.            
echo               [■■■■■■■■■■■■■■■■■■■■■■■■                        ]
Call :ogni
:: İndirilen OgnitorenKs.Toolbox.zip dosyası C:\OgnitorenKs.Toolbox klasörü içerisine çıkarılır.
Call :Powershell "Expand-Archive -Force 'C:\OgnitorenKs.Toolbox\OgnitorenKs.Toolbox.zip' 'C:\OgnitorenKs.Toolbox'"
:: Kısayollar masaüstüne gönderilir.
Call :Powershell "Expand-Archive -Force 'C:\OgnitorenKs.Toolbox\Files\lnk.zip' 'C:\Users\%username%\Desktop'"
cls
Call :bosluk
echo                       %R%[92m OgnitorenKs Toolbox Yükleniyor...%R%[0m
echo.            
echo               [■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■            ]
Call :ogni
:: İndirilen güncelleştirme dosya artığı silinir.
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\OgnitorenKs.Toolbox.zip" > NUL 2>&1
DEL /F /Q /A "C:\users\%username%\Desktop\OgnitorenKs.Toolbox.Setup.lnk" > NUL 2>&1
cls
Call :bosluk
echo        %R%[92m OgnitorenKs Toolbox yükleme işlemi başarıyla tamamlanmıştır.%R%[0m
echo.
echo               [■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■]
Call :ogni
for /f "tokens=2" %%a in ('echo %date%') do set timeupdate=%%a
set TimeUpdateDate=%timeupdate:~0,-8%.%timeupdate:~3,-5%.%timeupdate:~6%
for /f "tokens=2" %%a in ('findstr /i "TimeUpdate" C:\OgnitorenKs.Toolbox\Settings.ini') do (
	Call :Powershell "(Get-Content C:\OgnitorenKs.Toolbox\Settings.ini) | ForEach-Object { $_ -replace '%%a', '%TimeUpdateDate%' } | Set-Content 'C:\OgnitorenKs.Toolbox\Settings.ini'"
)
timeout /t 3 /nobreak > NUL
DEL /F /Q /A "C:\OgnitorenKs.Toolbox\Extra\OgnitorenKs.Toolbox.Setup.bat" > NUL 2>&1
exit

:bosluk
echo.
echo.
echo.
echo.
echo.
echo.
echo.
goto :eof
:ogni
echo.
echo              %R%[33m████ ████ █   █ █ █████ ████ ████ ███ █   █ █  █ ████%R%[0m
echo              %R%[33m█  █ █    ██  █ █   █   █  █ █  █ █   ██  █ █ █  █   %R%[0m
echo              %R%[33m█  █ █ ██ █ █ █ █   █   █  █ ████ ██  █ █ █ ██   ████%R%[0m
echo              %R%[33m█  █ █  █ █  ██ █   █   █  █ █ █  █   █  ██ █ █     █%R%[0m
echo              %R%[33m████ ████ █   █ █   █   ████ █  █ ███ █   █ █  █ ████%R%[0m
goto :eof
:netkontrol
Call :bosluk
echo                        %R%[91m INTERNET BAGLANTISI SAĞLANAMADI%R%[0m
echo. 
echo               [##################### HATA #####################]  
Call :ogni
timeout /t 7 /nobreak > NUL
goto :eof
:wget
Call :bosluk
echo                       %R%[92m Kurulum dosyaları indiriliyor...%R%[0m
echo.  
echo               [################################################]  
Call :ogni
mkdir C:\OgnitorenKs.Toolbox\Files > NUL 2>&1
Call :Powershell "& { iwr https://eternallybored.org/misc/wget/1.21.3/64/wget.exe -OutFile C:\OgnitorenKs.Toolbox\Files\wget.exe }"
timeout /t 1 /nobreak > NUL
cls
goto :eof

:Powershell
chcp 437 > NUL 2>&1
Powershell -command %*
chcp 65001 > NUL 2>&1
goto :eof


:ColorEnd
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set R=%%b
  exit /B 0
)
exit /B 0

