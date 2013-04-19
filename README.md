Warning!
========

This is only beta. It should be used in a production environments only with the crossed fingers on all the limbs, and is at your own risk.

Irv
===

Irv is a proof-of-concept of the improved request validation engine for ASP.NET Framework to prevent Type-1 (reflected) XSS attacks. It provides a higher security level than the original one because of extended logic of request validation and written from scratch response validation module. An approach to response validation is based on total integrity control of all parts of the output document, which can be potentially tainted by request parameters.

Demo
====

Online demo of the vulnerable web-application protected by Irv is available at http://irv.c2e.pw/Demo/

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

Security tests and performance benchmarks
=========================================

Irv has successfully passed a long and painful manual testing with a tons of various XSS vectors. Neither Acunetix WVS (http://www.acunetix.com/vulnerability-scanner/) nor Snuck (https://code.google.com/p/snuck/) aren't bypasses it too. Nevertheless Irv is still in beta and yet can contain some bugs and false-positives specific to certain web-applications.

Average page processing time for XSS vectors from the wild is near of 50-75ms, and a significant part of the Irv code is a still subject to optimization and improvement.
