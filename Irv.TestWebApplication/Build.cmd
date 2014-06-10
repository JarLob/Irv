rem @echo off

cd ..
call Build.cmd
cd %~dp0
   
"%ProgramFiles(x86)%\IIS Express\iisexpress" /path:%~dp0 /systray:false /clr:v4.0
