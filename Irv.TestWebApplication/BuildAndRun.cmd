rem @echo off
set MSBuild="%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe"

%MSBuild% Irv.TestWebApplication.csproj /tv:4.0 /p:TargetFrameworkVersion=v4.5;Configuration=Release

"%ProgramFiles(x86)%\IIS Express\iisexpress" /path:%~dp0 /systray:false /clr:v4.0
