set MSBuild="%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe"
%MSBuild% Irv.sln /p:TargetFrameworkVersion=v4.5;Configuration=Release

rem set MSTest="%VS110COMNTOOLS%\..\IDE\MSTest.exe"
rem %MSTest% /testcontainer:"%~dp0\Irv.Tests\bin\Debug\Irv.Tests.dll"
