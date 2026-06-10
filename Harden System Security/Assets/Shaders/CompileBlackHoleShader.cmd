@echo off
setlocal

set FXC_EXE=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\fxc.exe
set INCLUDEPATH=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um

"%FXC_EXE%" Assets\Shaders\BlackHoleShader.hlsl /nologo /T lib_4_0_level_9_3_ps_only /D D2D_FUNCTION /D D2D_ENTRY=main /Fl Assets\Shaders\BlackHoleShader.fxlib /I "%INCLUDEPATH%"
if errorlevel 1 exit /b 1

"%FXC_EXE%" Assets\Shaders\BlackHoleShader.hlsl /nologo /T ps_4_0_level_9_3 /D D2D_FULL_SHADER /D D2D_ENTRY=main /E main /setprivate Assets\Shaders\BlackHoleShader.fxlib /Fo:Assets\Shaders\BlackHoleShader.bin /I "%INCLUDEPATH%"
if errorlevel 1 exit /b 1

if exist Assets\Shaders\BlackHoleShader.fxlib del Assets\Shaders\BlackHoleShader.fxlib

endlocal