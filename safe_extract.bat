@echo off
REM safe_extract_simple.bat
REM Purpose: prompt once for INPUT/OUTPUT dirs, save to dirs.conf, extract archives using password "infected"
setlocal EnableExtensions EnableDelayedExpansion

:: ---- Config ----
set "CONFIG=%~dp0dirs.conf"
set "LOG=%~dp0extract.log"
set "PASSWORD=infected"
set "ARCHIVE_EXTS=7z zip rar tar gz tgz tbz2 tbz txz bz2 xz lzma wim iso cab arj z"
set "PROCESSED_DIR_NAME=processed"

:: ---- Help / Reset ----
if /I "%~1"=="/?" goto :usage
if /I "%~1"=="/help" goto :usage
if /I "%~1"=="/reset" (
    if exist "%CONFIG%" del /f /q "%CONFIG%"
    echo Configuration deleted.
    goto :end
)

:: ---- Load or ask for config ----
if exist "%CONFIG%" (
    for /f "usebackq delims=" %%A in ("%CONFIG%") do (
        if not defined INPUT_DIR set "INPUT_DIR=%%~A" & goto :nextline
    )
    :nextline
    for /f "skip=1 usebackq delims=" %%B in ("%CONFIG%") do (
        if not defined OUTPUT_DIR set "OUTPUT_DIR=%%~B"
    )
) 

if not defined INPUT_DIR (
    set /p "INPUT_DIR=Enter full INPUT directory (where archives are): "
    if "%INPUT_DIR%"=="" (
        echo No input specified. Exiting.
        goto :end
    )
    set /p "OUTPUT_DIR=Enter full OUTPUT directory (where extracted files will go): "
    if "%OUTPUT_DIR%"=="" (
        echo No output specified. Exiting.
        goto :end
    )
    >"%CONFIG%" echo %INPUT_DIR%
    >>"%CONFIG%" echo %OUTPUT_DIR%
    echo [INFO] Saved configuration to "%CONFIG%" >> "%LOG%"
    echo Configuration saved.
) else (
    echo Using saved config:
    echo Input:  "%INPUT_DIR%"
    echo Output: "%OUTPUT_DIR%"
)

:: ---- Normalize paths (remove trailing backslash) ----
call :normpath INPUT_DIR INPUT_DIR
call :normpath OUTPUT_DIR OUTPUT_DIR

:: ---- Validate directories ----
if not exist "%INPUT_DIR%" (
    echo [ERROR] Input directory "%INPUT_DIR%" does not exist. Exiting.
    echo [ERROR] Input directory does not exist. >> "%LOG%"
    goto :end
)
if not exist "%OUTPUT_DIR%" md "%OUTPUT_DIR%" 2>nul

:: ---- Ensure processed folder inside input to avoid reprocessing ----
set "PROCESSED_DIR=%INPUT_DIR%\%PROCESSED_DIR_NAME%"
if not exist "%PROCESSED_DIR%" md "%PROCESSED_DIR%" 2>nul

:: ---- Find 7z ----
set "SEVENZIP="
if exist "%ProgramFiles%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles%\7-Zip\7z.exe"
if not defined SEVENZIP if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles(x86)%\7-Zip\7z.exe"
if not defined SEVENZIP (
    where 7z >nul 2>&1
    if not errorlevel 1 for /f "usebackq delims=" %%Z in (`where 7z 2^>nul`) do set "SEVENZIP=%%Z"
)
if not defined SEVENZIP (
    echo [ERROR] 7z.exe not found. Install 7-Zip or place 7z.exe on PATH.
    echo [ERROR] 7z.exe not found. >> "%LOG%"
    goto :end
)

echo [INFO] Using 7z: "%SEVENZIP%" >> "%LOG%"
echo Starting extraction run... >> "%LOG%"

:: ---- Process top-level files in INPUT_DIR (non-recursive) ----
pushd "%INPUT_DIR%" || ( echo [ERROR] Cannot access input dir. & goto :end )
for %%F in ("%INPUT_DIR%\*.*") do (
    set "file=%%~fF"
    call :process "%%~fF"
)
popd

echo Extraction run complete. See "%LOG%" for details.
echo Processed originals moved to: "%PROCESSED_DIR%"
goto :end

:: -----------------------
:: Subroutines
:: -----------------------

:process
REM %1 = full path to candidate file
setlocal EnableDelayedExpansion
set "ARCH=%~1"
if not exist "!ARCH!" endlocal & exit /b 0

set "EXT=%~x1"
if defined EXT (
    set "EXT=!EXT:~1!"
) else (
    endlocal & exit /b 0
)

call :is_archive "!EXT!" ISARC
if not "!ISARC!"=="1" (
    endlocal & exit /b 0
)

set "BASENAME=%~n1"
set "DEST=%OUTPUT_DIR%\!BASENAME!_%RANDOM%"
md "!DEST!" 2>nul

echo [INFO] Extracting "!ARCH!" -> "!DEST!" >> "%LOG%"
"%SEVENZIP%" x -p"%PASSWORD%" -y -o"!DEST!" "!ARCH!" >> "%LOG%" 2>&1
if errorlevel 1 (
    echo [ERROR] Extraction failed for "!ARCH!". See log. >> "%LOG%"
) else (
    echo [OK] Extracted "!ARCH!" to "!DEST!" >> "%LOG%"
    REM Move original archive to processed folder to avoid reprocessing
    move /Y "!ARCH!" "%PROCESSED_DIR%\" >> "%LOG%" 2>&1
)
endlocal
exit /b 0

:is_archive
REM %1 = extension (no dot), returns %2 = 1 if archive, else 0
setlocal EnableDelayedExpansion
set "e=%~1"
set "res=0"
for %%x in (%ARCHIVE_EXTS%) do (
    if /I "%%x"=="!e!" set "res=1"
)
endlocal & set "%~2=%res%"
exit /b 0

:normpath
REM params: %1 var input name, %2 var output name
setlocal EnableDelayedExpansion
set "p=!%~1!"
if "!p:~-1!"=="\" set "p=!p:~0,-1!"
endlocal & set "%~2=%p%"
exit /b 0

:usage
echo Usage: safe_extract_simple.bat [ /reset ]
echo First run will prompt for Input and Output directories and save them to dirs.conf.
goto :end

:end
endlocal
exit /b 0
