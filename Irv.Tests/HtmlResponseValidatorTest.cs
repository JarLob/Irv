using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Irv.Engine;

namespace Irv.Tests
{
    [TestClass]
    public class HtmlResponseValidatorTest
    {
        public TestContext TestContext { get; set; }

        [DeploymentItem(@"TestData\XssTriviaTagInjection.testscript")]
        [TestMethod]
        public void TriviaTagInjection()
        {
            TestScriptRunner("XssTriviaTagInjection");
        }

        [DeploymentItem(@"TestData\XssEscapedJsInjection.testscript")]
        [TestMethod]
        public void EscapedJsInjection()
        {
            TestScriptRunner("XssEscapedJsInjection");
        }

        [DeploymentItem(@"TestData\XssEscapedAttrInjection.testscript")]
        [TestMethod]
        public void EscapedAttrInjection()
        {
            TestScriptRunner("XssEscapedAttrInjection");
        }

        [DeploymentItem(@"TestData\XssFragmentedInjectionx2.testscript")]
        [TestMethod]
        public void FragmentedInjectionx2()
        {
            TestScriptRunner("XssFragmentedInjectionx2");
        }

        [DeploymentItem(@"TestData\XssFragmentedInjectionx3.testscript")]
        [TestMethod]
        public void FragmentedInjectionx3()
        {
            TestScriptRunner("XssFragmentedInjectionx3");
        }

        [DeploymentItem(@"TestData\XssUriInjection.testscript")]
        [TestMethod]
        public void UriInjection()
        {
            TestScriptRunner("XssUriInjection");
        }

        private void TestScriptRunner(string testName)
        {
            var scriptLines = File.ReadAllLines(string.Format("{0}.testscript", testName));
            var templateBuilder = new StringBuilder();
            var currentScriptLine = 0;

            do
            {
                if (scriptLines[currentScriptLine] != string.Empty)
                {
                    templateBuilder.AppendLine(scriptLines[currentScriptLine]);
                }
            } while (scriptLines[++currentScriptLine] != "<!--End-of-template-->");

            currentScriptLine++;

            var responseTemplate = templateBuilder.ToString();

            var paramList = new List<string>();

            while (currentScriptLine < scriptLines.Length)
            {
                if (scriptLines[currentScriptLine].Length == 0)
                {
                    if (paramList.Count > 0)
                    {
// ReSharper disable CoVariantArrayConversion
                        var responseText = string.Format(responseTemplate, paramList.ToArray());
// ReSharper restore CoVariantArrayConversion

                        var validator = new HtmlResponseValidator();
                        var taintfulParams =
                            paramList.Select(param => new RequestValidationParam("Irv.Tests", "None", param)).ToList();
                        RequestValidationParam dangerousParam;
                        var validationResult = validator.IsValidHtmlResponseString(taintfulParams, responseText,
                                                                                   out dangerousParam);
                        if (validationResult)
                        {
                            TestContext.WriteLine("Test {0} failed on param(s): {{ {1} }}", testName,
                                                  string.Join("} {", paramList));
                        }

                        Assert.IsFalse(validationResult);
                        paramList.Clear();
                    }
                }
                else
                {
                    paramList.Add(HttpUtility.UrlDecode(scriptLines[currentScriptLine]));
                }
                currentScriptLine++;
            }
        }
    }
}
