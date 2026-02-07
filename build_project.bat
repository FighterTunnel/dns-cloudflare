@echo off
echo Installing dependencies...
python -m pip install -r requirements.txt

echo Building project with PyInstaller...
python -m PyInstaller --clean --onefile --windowed --name "CloudflareManager" main.py

echo Moving executable...
move /Y dist\CloudflareManager.exe .

echo Cleaning up build files...
rmdir /s /q build dist
del CloudflareManager.spec

echo.
echo Build Complete! CloudflareManager.exe is ready in this folder.
pause
