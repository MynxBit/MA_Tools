@echo off
REM safe_extract_full.bat
REM Version: 2025-09-12
REM Purpose: Robust, safe extraction of archives using 7z with persistent config, nested extraction,
REM quarantine of risky files, logging and error handling.
REM Default extraction password: infected
setlocal EnableExtensions EnableDelayedExpansion

:: ---------------------------
:: Configurable constants
:: ---------------------------
set "CONFIG=%~dp0dirs.conf"
set "LOG=%~dp0extract.log"
set "TMP_OUT=%~dp0.7z_temp_output.txt"
set "PASSWORD=infected"
set "QUARANTINE_NAME=quarantine"
set "NESTED_EXTRACTION=1"    REM 1 = enable nested archive extraction, 0 = disable
set "MAX_NESTED_DEPTH=3"    REM maximum nested extraction iterations (prevents infinite loops)
set "ARCHIVE_EXTS=7z zip rar tar gz tgz tbz2 tbz txz bz2 xz lzma wim iso cab arj z"
set "RISKY_EXTS=exe dll bat cmd ps1 vbs js scr msi"

:: ---------------------------
:: Usage / switches
:: ---------------------------
if /I "%~1"=="/?" goto :usage
if /I "%~1"=="/help" goto :usage
if /I "%~1"=="/reset" (
    if exist "%CONFIG%" del /f /q "%CONFIG%" >nul 2>&1
    echo Configuration reset (deleted "%CONFIG%").
)
if /I "%~1"=="/reconfig" (
    if exist "%CONFIG%" del /f /q "%CONFIG%" >nul 2>&1
    echo Forcing reconfiguration...
)

:: ---------------------------
:: Helper: timestamp
:: ---------------------------
call :timestamp TIMESTAMP

:: ---------------------------
:: Load config or prompt user
:: ---------------------------
if exist "%CONFIG%" (
    set "LINECNT=0"
    for /f "usebackq delims=" %%A in ("%CONFIG%") do (
        set /a LINECNT+=1
        if !LINECNT! equ 1 set "INPUT_DIR=%%~A"
        if !LINECNT! equ 2 set "OUTPUT_DIR=%%~A"
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
    echo [%TIMESTAMP%] Saved configuration to "%CONFIG%" >> "%LOG%"
    echo Configuration saved.
) else (
    echo Using saved config:
    echo Input:  "%INPUT_DIR%"
    echo Output: "%OUTPUT_DIR%"
)

:: Normalize paths (remove trailing backslash)
call :normpath INPUT_DIR INPUT_DIR
call :normpath OUTPUT_DIR OUTPUT_DIR

:: Validate input directory
if not exist "%INPUT_DIR%" (
    echo [ERROR] Input directory "%INPUT_DIR%" does not exist. Exiting.
    echo [%TIMESTAMP%] ERROR: Input directory "%INPUT_DIR%" does not exist. >> "%LOG%"
    goto :end
)

:: Create output directory if missing
if not exist "%OUTPUT_DIR%" (
    md "%OUTPUT_DIR%" 2>nul
    if errorlevel 1 (
        echo [ERROR] Failed to create output directory "%OUTPUT_DIR%". Exiting.
        echo [%TIMESTAMP%] ERROR: Failed to create output directory "%OUTPUT_DIR%". >> "%LOG%"
        goto :end
    )
)

:: Create quarantine directory
set "QUARANTINE_DIR=%OUTPUT_DIR%\%QUARANTINE_NAME%"
if not exist "%QUARANTINE_DIR%" md "%QUARANTINE_DIR%" 2>nul

:: ---------------------------
:: Find 7z.exe
:: ---------------------------
set "SEVENZIP="
if exist "%ProgramFiles%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles%\7-Zip\7z.exe"
if not defined SEVENZIP if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles(x86)%\7-Zip\7z.exe"
if not defined SEVENZIP (
    where 7z >nul 2>&1
    if not errorlevel 1 for /f "usebackq delims=" %%Z in (`where 7z 2^>nul`) do set "SEVENZIP=%%Z"
)
if not defined SEVENZIP (
    echo [ERROR] 7z.exe not found. Install 7-Zip or ensure 7z.exe is on PATH.
    echo [%TIMESTAMP%] ERROR: 7z.exe not found. >> "%LOG%"
    goto :end
)
echo Using 7z: "%SEVENZIP%"
echo [%TIMESTAMP%] Using 7z: "%SEVENZIP%" >> "%LOG%"

:: ---------------------------
:: Begin extraction loop
:: ---------------------------
echo.
echo Starting extraction run...
echo [%TIMESTAMP%] Starting extraction run. Input="%INPUT_DIR%", Output="%OUTPUT_DIR%". >> "%LOG%"

pushd "%INPUT_DIR%" || (
    echo [ERROR] Cannot access input directory "%INPUT_DIR%".
    echo [%TIMESTAMP%] ERROR: Cannot access input directory. >> "%LOG%"
    goto :end
)

REM Process non-recursively first-run archives in INPUT_DIR
for %%F in ("%INPUT_DIR%\*.*") do (
    call :process_archive "%%~fF"
)

popd

:: Nested extraction loop (if enabled) - prevents infinite loops by limiting depth
if "%NESTED_EXTRACTION%"=="1" (
    set /a DEPTH=0
    :nested_loop
    if %DEPTH% GEQ %MAX_NESTED_DEPTH% goto :nested_done
    set /a DEPTH+=1
    set "FOUND_NESTED=0"
    for /R "%OUTPUT_DIR%" %%A in (*.*) do (
        set "ext=%%~xA"
        set "ext=!ext:~1!"
        call :is_archive "!ext!" ISARC
        if "!ISARC!"=="1" (
            set "FOUND_NESTED=1"
            call :process_archive "%%~fA"
        )
    )
    if "%FOUND_NESTED%"=="1" goto :nested_loop
    :nested_done
)

:: Post-processing: quarantine risky files found in OUTPUT_DIR (skips files already in quarantine)
echo [%TIMESTAMP%] Scanning for risky file types to quarantine... >> "%LOG%"
for /R "%OUTPUT_DIR%" %%G in (*.exe *.dll *.bat *.cmd *.ps1 *.vbs *.js *.scr *.msi) do (
    set "full=%%~fG"
    echo "!full!" | findstr /I /C:"\%QUARANTINE_NAME%\" >nul
    if errorlevel 1 (
        echo [%TIMESTAMP%] Quarantining: "%%~fG" >> "%LOG%"
        move /Y "%%~fG" "%QUARANTINE_DIR%\" >> "%LOG%" 2>&1
    ) else (
        echo [%TIMESTAMP%] Skipping already quarantined: "%%~fG" >> "%LOG%"
    )
)

call :timestamp ENDTS
echo.
echo Extraction run complete. See "%LOG%" for details.
echo Risky files (if any) moved to: "%QUARANTINE_DIR%"
echo.
goto :end

:: ---------------------------
:: Subroutines
:: ---------------------------

:process_archive
REM %1 = full path to candidate file
set "ARCH=%~1"
if not exist "%ARCH%" goto :pa_done
set "BASENAME=%~n1"
set "EXT=%~x1"
set "EXT=%EXT:~1%"
call :is_archive "%EXT%" ISARC
if not "%ISARC%"=="1" goto :pa_done

REM Build destination folder inside OUTPUT_DIR named after archive file (timestamped to avoid collisions)
call :timestamp TSTAMP
set "DEST=%OUTPUT_DIR%\%BASENAME%_%TSTAMP%"
md "%DEST%" 2>nul

echo [%TSTAMP%] Extracting "%ARCH%" -> "%DEST%" >> "%LOG%"
REM Run 7z and capture output
"%SEVENZIP%" x -p"%PASSWORD%" -y -o"%DEST%" "%ARCH%" >"%TMP_OUT%" 2>&1
if errorlevel 1 (
    echo [%TSTAMP%] FAILED: Extraction failed for "%ARCH%". See temp output. >> "%LOG%"
    type "%TMP_OUT%" >> "%LOG%"
    echo ---------- >> "%LOG%"
) else (
    echo [%TSTAMP%] OK: Extracted "%ARCH%" to "%DEST%". >> "%LOG%"
    echo ---------- >> "%LOG%"
    REM Optionally, mark the original archive as processed to avoid reprocessing nested extraction loops.
    REM We will rename the original archive by appending .processed (safe operation)
    if exist "%ARCH%" (
        ren "%ARCH%" "%%~nx1.processed" >nul 2>&1
    )
)
del "%TMP_OUT%" 2>nul
:pa_done
exit /b 0

:is_archive
REM %1 extension string (no dot), returns ISARC var (1 or 0)
setlocal EnableDelayedExpansion
set "e=%~1"
set "result=0"
for %%x in (%ARCHIVE_EXTS%) do (
    if /I "%%x"=="!e!" set "result=1"
)
endlocal & set "%~2=%result%"
exit /b 0

:normpath
REM normalize path: remove trailing backslash if present
REM params: %1 = var name input, %2 = var name output
setlocal
set "p=!%~1!"
if "!p:~-1!"=="\" set "p=!p:~0,-1!"
endlocal & set "%~2=%p%"
exit /b 0

:timestamp
REM returns timestamp in format YYYYMMDD_HHMMSS in variable named by %1
for /f "tokens=1-3 delims=/.- " %%a in ('echo ^%date^%') do (
    set "_d=%%a-%%b-%%c"
)
set "_t=%time: =0%"
set "_t=%_t::=%"
set "ts=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
REM Fallback if above parsing varies; create safe timestamp
for /f "tokens=1-4 delims=:/,." %%A in ("%DATE% %TIME%") do set "TSFMT=%%A_%%B_%%C_%%D"
set "%1=%TSFMT%"
exit /b 0

:usage
echo Usage: safe_extract_full.bat [ /reset | /reconfig ]
echo.
echo Behavior:
echo   - On first run the script will prompt for Input and Output directories and save them to dirs.conf.
echo   - /reset  -> deletes dirs.conf (resets saved config).
echo   - /reconfig -> deletes and forces reconfiguration at next prompt.
echo Notes:
echo   - Requires 7z.exe (7-Zip CLI) installed or on PATH.
echo   - Default extraction password is "%PASSWORD%" (change in script if needed).
echo   - Script will NOT execute any extracted files. Risky files are moved to %QUARANTINE_NAME% inside output.
goto :end

:end
endlocal
exit /b 0
