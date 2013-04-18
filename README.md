Warning!
========

This is a deeply beta. It's still on PoC stage and should not be used in production sites.

Irv
===

Irv is a Proof-of-Concept improved request validation engine for ASP.NET Framework to prevent Type-1 (reflected) XSS attacks. It provides a higher security level than the original one because of extended logic of request validation and written from scratch response validation module. Response validation approach is based on total integrity control of all parts of the output document, which can be potentially tainted by request parameters.

Demo
====

Online demo of vulnerable web-application protected by Irv is available at http://irv.c2e.pw/Demo/

Install
=======

Put all Irv's assemblies to GAC or '\bin' directory of ASP.NET project. Add following lines to corresponding sections of 'web.config' file::

```xml
    <configuration>
      <system.web>
        <httpRuntime targetFramework="4.5" requestValidationType="Irv.Engine.XssRequestValidator" />
      </system.web>
      <system.webServer>
        <modules>
          <add name="Irv.Engine.dll" type="Irv.Engine.XssResponseValidationModule" />
        </modules>
      </system.webServer>
    </configuration>
```
