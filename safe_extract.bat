@echo off
REM safe_extract.bat
REM Batch script to extract archives from an input directory to an output directory using 7z
REM Saves configuration in dirs.conf in same folder. Default extraction password: infected
REM Moves risky files (exe, dll, bat, cmd, ps1, vbs, js, scr, msi) to a quarantine subfolder.
setlocal enabledelayedexpansion

REM ---------- Configuration ----------
set "CONFIG=%~dp0dirs.conf"
set "LOG=%~dp0extract.log"
set "PASSWORD=infected"
set "QUARANTINE_NAME=quarantine"

REM ---------- Helper: timestamp ----------
for /f "tokens=1-3 delims=/.- " %%a in ('echo ^%date^%') do set _d=%%a-%%b-%%c
set "_t=%time: =0%"
set "TIMESTAMP=%_d%_%_t%"

REM ---------- Parse args ----------
if /I "%~1"=="/reset" (
    if exist "%CONFIG%" del /f /q "%CONFIG%"
    echo Configuration reset. You will be prompted for directories on next run.
)

REM ---------- Load config or prompt ----------
if exist "%CONFIG%" (
    for /f "usebackq delims=" %%A in ("%CONFIG%") do (
        if not defined INPUT_DIR set "INPUT_DIR=%%~A" & goto :nextline
        if not defined OUTPUT_DIR set "OUTPUT_DIR=%%~A"
    )
) 

:nextline
if not defined INPUT_DIR (
    set /p "INPUT_DIR=Enter full INPUT directory (where archives are): "
    if "%INPUT_DIR%"=="" (
        echo No input directory provided. Exiting.
        goto :end
    )
    set /p "OUTPUT_DIR=Enter full OUTPUT directory (where extracted files will go): "
    if "%OUTPUT_DIR%"=="" (
        echo No output directory provided. Exiting.
        goto :end
    )
    REM Save to config
    >"%CONFIG%" echo %INPUT_DIR%
    >>"%CONFIG%" echo %OUTPUT_DIR%
    echo Configuration saved to "%CONFIG%".
)

REM ---------- Validate directories ----------
if not exist "%INPUT_DIR%" (
    echo [!] Input directory "%INPUT_DIR%" does not exist. Exiting.
    goto :end
)
if not exist "%OUTPUT_DIR%" (
    echo Output directory "%OUTPUT_DIR%" does not exist. Creating...
    md "%OUTPUT_DIR%" 2>nul
    if errorlevel 1 (
        echo [!] Failed to create output directory "%OUTPUT_DIR%". Exiting.
        goto :end
    )
)

REM ---------- Find 7z.exe ----------
set "SEVENZIP="
if exist "%ProgramFiles%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles%\7-Zip\7z.exe"
if not defined SEVENZIP if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SEVENZIP=%ProgramFiles(x86)%\7-Zip\7z.exe"
if not defined SEVENZIP (
    for %%P in ("%ProgramFiles%\7-Zip\7z.exe" "%ProgramFiles(x86)%\7-Zip\7z.exe") do (
        if exist "%%~P" set "SEVENZIP=%%~P"
    )
)
REM Also allow 7z on PATH
if not defined SEVENZIP (
    where 7z >nul 2>&1
    if not errorlevel 1 for /f "usebackq delims=" %%Z in (`where 7z`) do set "SEVENZIP=%%Z"
)

if not defined SEVENZIP (
    echo [!] 7z.exe not found. Please install 7-Zip or ensure 7z.exe is on PATH.
    echo Aborting.
    goto :end
)

echo Using 7z: "%SEVENZIP%"

REM ---------- Prepare quarantine folder ----------
set "QUARANTINE_DIR=%OUTPUT_DIR%\%QUARANTINE_NAME%"
if not exist "%QUARANTINE_DIR%" md "%QUARANTINE_DIR%"

REM ---------- Archive extensions (lowercase, no leading dot) ----------
REM Add or remove extensions here as needed
set "EXTS=7z zip rar tar gz tgz tbz2 tbz txz bz2 xz lzma wim iso cab arj z"

REM ---------- Start processing ----------
echo [%TIMESTAMP%] Starting extraction >> "%LOG%"
echo Input: "%INPUT_DIR%" >> "%LOG%"
echo Output: "%OUTPUT_DIR%" >> "%LOG%"
echo ---------- >> "%LOG%"

pushd "%INPUT_DIR%" || (echo [!] Cannot pushd to input dir & goto :end)

REM Iterate files in INPUT_DIR (non-recursive). Use full path with %%F
for %%F in ("%INPUT_DIR%\*.*") do (
    set "FILE=%%~fF"
    set "NAME=%%~nF"
    set "EXT=%%~xF"
    REM Normalize extension to lowercase and remove leading dot
    set "EXT=!EXT:~1!"
    for %%L in (!EXTS!) do (
        if /I "%%L"=="!EXT!" (
            echo Processing "%%~fF"...
            REM Create dedicated subfolder per archive to avoid file collisions
            set "DEST=%OUTPUT_DIR%\!NAME!"
            if not exist "!DEST!" md "!DEST!"
            REM Extract with password - suppress output but capture errorlevel
            "%SEVENZIP%" x -p"%PASSWORD%" -y -o"!DEST!" "%%~fF" >"%~dp0temp_extract_out.txt" 2>&1
            if errorlevel 1 (
                echo [%DATE% %TIME%] FAILED: "%%~fF" >> "%LOG%"
                echo Extraction failed for "%%~fF". See temp_extract_out.txt for details.
                type "%~dp0temp_extract_out.txt" >> "%LOG%"
                echo ---------- >> "%LOG%"
            ) else (
                echo [%DATE% %TIME%] OK: "%%~fF" extracted to "!DEST!" >> "%LOG%"
                echo ---------- >> "%LOG%"
            )
            del "%~dp0temp_extract_out.txt" 2>nul
        )
    )
)

popd

REM ---------- Post-extraction: quarantine risky files ----------
echo [%DATE% %TIME%] Scanning for risky file types to quarantine... >> "%LOG%"
for /R "%OUTPUT_DIR%" %%G in (*.exe *.dll *.bat *.cmd *.ps1 *.vbs *.js *.scr *.msi) do (
    REM Do not quarantine files already in the quarantine folder
    echo "%%~fG" | findstr /I /C:"\%QUARANTINE_NAME%\" >nul
    if errorlevel 1 (
        echo Quarantining: "%%~fG" >> "%LOG%"
        move /Y "%%~fG" "%QUARANTINE_DIR%\" >> "%LOG%" 2>&1
    ) else (
        REM already in quarantine; skip
        echo Skipping (already in quarantine): "%%~fG" >> "%LOG%"
    )
)

echo [%DATE% %TIME%] Done. >> "%LOG%"
echo Extraction complete. See "%LOG%" for details.
echo Risky files, if any, moved to: "%QUARANTINE_DIR%"

:end
endlocal
exit /b 0
