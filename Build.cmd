set MSBuild="%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe"

.nuget\nuget restore Irv.sln
%MSBuild% Irv.sln /p:TargetFrameworkVersion=v4.5;Configuration=Release

set MSTest="%VS120COMNTOOLS%\..\IDE\MSTest.exe"
%MSTest% /testcontainer:"%~dp0\Irv.Tests\bin\Release\Irv.Tests.dll"
