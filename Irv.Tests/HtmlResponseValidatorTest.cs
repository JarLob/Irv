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

        [TestMethod]
        public void TriviaTagInjection()
        {
            TestScriptRunner("TriviaTagInjection");
        }

        [TestMethod]
        public void EscapedJsInjection()
        {
            TestScriptRunner("EscapedJsInjection");
        }

        [TestMethod]
        public void EscapedAttrInjection()
        {
            TestScriptRunner("EscapedAttrInjection");
        }

        [TestMethod]
        public void FragmentedInjection()
        {
            TestScriptRunner("FragmentedInjection");
        }

        [TestMethod]
        public void UriInjection()
        {
            TestScriptRunner("UriInjection");
        }

        private void TestScriptRunner(string testName)
        {
            var scriptLines = File.ReadAllLines(string.Format("{0}\\TestScripts\\{1}.testscript", Directory.GetCurrentDirectory(), testName));
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
                        string responseText;

                        switch (paramList.Count)
                        {
                            case 1:
                                responseText = string.Format(responseTemplate, paramList[0]);
                                break;

                            case 2:
                                responseText = string.Format(responseTemplate, paramList[0], paramList[1]);
                                break;

                            default:
                                throw new NotImplementedException();
                        }

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
