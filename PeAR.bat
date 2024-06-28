:: Max python version PeAR supports is python3.10, as gtirb python libs don't work with higher versions.
:: Find ddisasm and gtirb-pprinter binaries here: https://download.grammatech.com/gtirb/files/windows-release/
:: You will need to to add them to your path and probably run them once to dismiss the virus popup.

@echo off
python --version 2>nul | find "Python 3" >nul
if %errorlevel% equ 0 (
    python -m pear %*
) else (
    echo "Please install Python 3 (highest supported version is 3.10), then install dependencies with: python -m pip install -r .\requirements.txt"
)
