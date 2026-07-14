@echo off
REM KellectConsole Qt5.15 build/test (Ninja + vcvars cl 14.29 / SDK 19041)
REM Usage: cmd //c scripts\build.bat        build only
REM        cmd //c scripts\build.bat test   build + ctest
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 10.0.19041.0 -vcvars_ver=14.29
if errorlevel 1 exit /b 1
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=D:/Code/Qt/5.15.2-static -DCMAKE_SYSTEM_VERSION=10.0.19041.0 -DCMAKE_EXE_LINKER_FLAGS=/MANIFEST:NO
if errorlevel 1 exit /b 1
cmake --build build
if errorlevel 1 exit /b 1
if not "%1"=="" ctest --test-dir build --output-on-failure
