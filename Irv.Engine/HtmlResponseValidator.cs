using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Antlr.Runtime;
using Antlr.Runtime.Tree;
using HtmlAgilityPack;
using JsParser.Net;

namespace Irv.Engine
{
    internal class HtmlResponseValidator
    {
        // Minimal length of LCS for taintful param and fragment of response to threat it as potentially dangerous
        private const int LcsLengthTreshold = 7;
        // Minimal count of tokens of parsed code to threat it as potentially dangerous
        private const int TokensCountTreshold = 4;
        // Minimal count of nodes at AST of parsed code to threat it as potentially dangerous
        private const int AstNodesCountTreshold = 1;
        // Hint: because of 'alert(0)' consist of 2 nodes, 5 tokens and 7 symbols :D

        // HTML event-hanlders attributes names
        private readonly string[] _htmlEventHanlders =
            {
                "fscommand", "onabort", "onactivate", "onafterprint",
                "onafterupdate", "onbeforeactivate", "onbeforecopy", "onbeforecut", "onbeforedeactivate",
                "onbeforeeditfocus", "onbeforepaste", "onbeforeprint", "onbeforeunload", "onbegin", "onblur", "onbounce",
                "oncanplay", "oncanplaythrough", "oncellchange", "onchange", "onclick", "oncontextmenu", "oncontrolselect",
                "oncopy", "oncut", "ondataavailable", "ondatasetchanged", "ondatasetcomplete", "ondblclick", "ondeactivate",
                "ondrag", "ondragdrop", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop",
                "ondurationchange", "onemptied", "onend", "onended", "onerror", "onerrorupdate", "onfilterchange",
                "onfinish", "onfocus", "onfocusin", "onfocusout", "onformchange", "onforminput", "onhaschange", "onhelp",
                "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onlayoutcomplete", "onload", "onloadeddata",
                "onloadedmetadata", "onloadstart", "onlosecapture", "onmediacomplete", "onmediaerror", "onmessage",
                "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup",
                "onmousewheel", "onmove", "onmoveend", "onmovestart", "onoffline", "ononline", "onoutofsync", "onpagehide",
                "onpageshow", "onpaste", "onpause", "onplay", "onplaying", "onpopstate", "onprogress", "onpropertychange",
                "onratechange", "onreadystatechange", "onredo", "onrepeat", "onreset", "onresize", "onresizeend",
                "onresizestart", "onresume", "onreverse", "onrowdelete", "onrowexit", "onrowinserted", "onrowsenter",
                "onscroll", "onseek", "onseeked", "onseeking", "onselect", "onselectionchange", "onselectstart", "onstalled",
                "onstart", "onstop", "onstorage", "onsubmit", "onsuspend", "onsyncrestored", "ontimeerror", "ontimeupdate",
                "ontrackchange", "onundo", "onunload", "onurlflip", "onvolumechange", "onwaiting", "seeksegmenttime"
            };

        // HTML reference type attributes name
        private readonly string[] _htmlRefAttrs =
            {
                "src", "href", "background", "dynsrc", "lowsrc"
            };

        private readonly string[] _dangerousUriSchemes =
            {
                "data", "javascript", "vbscript", "livescript"
            };

        public bool IsValidHtmlResponseString(List<RequestValidationParam> taintfulParams, string responseText, out RequestValidationParam dangerousParam)
        {
            dangerousParam = null;

            // HACK: Deny null-byte injection techniques. Perhaps, there are a better place and method to implement it.
            if (responseText.IndexOf('\0') != -1)
            {
                dangerousParam = new RequestValidationParam("null-byte", "Undefined", "...\\0");
                return false;
            }

            var htmlDocument = new HtmlDocument();
            htmlDocument.LoadHtml(responseText);

            if (htmlDocument.DocumentNode == null) return true;

            // Get boundaries for all occurences of request params in response text
            var insertionsMap =
                InsertionsMap.FindAllPrecise(
                    taintfulParams,
                    responseText);

            if (insertionsMap.Count == 0) return true;

            // In case of parse errors, needed a check that positions of errors isn't included to insertions map
            if (htmlDocument.ParseErrors != null && htmlDocument.ParseErrors.Count() != 0)
            {
                foreach (var htmlParseError in htmlDocument.ParseErrors)
                {
                    foreach (var insertionArea in insertionsMap)
                    {
                        if (!insertionArea.Includes(htmlParseError.StreamPosition)) continue;

                        // Inclusion found (integrity of response has been violated by request parameter at error position)
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                }
            }

            // Walk through elements of parsed response to check its integrity
            foreach (
                var node in
                    htmlDocument.DocumentNode.Descendants()
                                .Where(x => x.NodeType == HtmlNodeType.Element))
            {
                var nodeBeginPosition = node.StreamPosition;
                var nodeEndPosition = nodeBeginPosition + node.OuterHtml.Length;

                foreach (
                    var insertionArea in
                        insertionsMap.Where(ia => ia.Includes(nodeBeginPosition, nodeEndPosition)))
                {
                    // HACK: Deny IE related bypass technique (http://www.securityfocus.com/archive/1/524043)
                    if (node.OuterHtml.Contains("<%") && (insertionArea.Param.Value.Contains("<%")))
                    {
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                    // Check if start position of node is included to insertions map
                    if (insertionArea.Includes(nodeBeginPosition))
                    {
                        // Inclusion found (node was injected by request parameter)
                        dangerousParam = insertionArea.Param;
                        return false;
                    }

                    foreach (var attr in node.Attributes)
                    {
                        var attrNameBeginPosition = attr.StreamPosition;

                        if (insertionArea.Includes(attrNameBeginPosition))
                        {
                            // Inclusion found (attribute was injected by request parameter)
                            dangerousParam = insertionArea.Param;
                            return false;
                        }

                        var attrValueBeginPosition = responseText.IndexOf(attr.Value, attrNameBeginPosition,
                                                                            StringComparison.Ordinal);
                        var attrValueEndPosition = attrValueBeginPosition + attr.Value.Length;

                        // Skip if attribute value doesn't tainted by request parameter
                        if (!insertionArea.Includes(attrValueBeginPosition, attrValueEndPosition)) continue;

                        // Skip if attribute value passed validation
                        if (ValidateAttrWithParam(attr.Name, attr.Value, insertionArea.Param.Value)) continue;

                        // Attribute value is dangerously tainted
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                }

                if (node.Name != "script" || string.IsNullOrEmpty(node.InnerText)) continue;

                // Validate javscript code inside <script /> tag
                var scriptBeginPosition = responseText.IndexOf(node.InnerText, nodeBeginPosition, StringComparison.Ordinal);
                var scriptEndPosition = scriptBeginPosition + node.InnerText.Length;

                foreach (
                    var insertionArea in
                        insertionsMap.Where(ia => ia.Includes(scriptBeginPosition, scriptEndPosition)))
                {
                    if (ValidateJsWithParam(node.InnerText, insertionArea.Param.Value)) continue;

                    // Javascript code is dangerously tainted
                    dangerousParam = insertionArea.Param;
                    return false;
                }

                if (node.Name != "style" || string.IsNullOrEmpty(node.InnerText)) continue;

                // TODO: Add integrity validation of style nodes
            }
            return true;
        }

        private bool ValidateAttrWithParam(string attrName, string attrValue, string paramValue)
        {
            if (_htmlEventHanlders.Contains(attrName))
            {
                return ValidateJsWithParam(attrValue, paramValue);
            }

            if (_htmlRefAttrs.Contains(attrName))
            {
                if (attrValue.Contains("&#")) return false;

                Uri uri;
                var result = Uri.TryCreate(attrValue, UriKind.RelativeOrAbsolute, out uri);
                try
                {
                    // Deny dangerous and malformed schemes (InvalidOperationException will be thrown at second case)s
                    if (uri.IsAbsoluteUri && (_dangerousUriSchemes.Contains(uri.Scheme))) return false;
                }
                // Scheme part is malformed with whitespace characters
                catch (InvalidOperationException)
                {
                    result = false;
                }
                return result;
            }

            if (attrName == "style")
            {
                // TODO: Add integrity validation of style attrs
                return true;
            }

            return true;
        }

        private bool ValidateJsWithParam(string jsValue, string paramValue)
        {
            CommonTree tree;
            string lcs;
            // Javascript code integrity was violated by request param
            if (!IsValidJsCode(jsValue, out tree)) return false;

            // Skip if common part of attribute value and taintful parameter less than defined treshhold
            return LongestCommonSubstring(jsValue, paramValue, out lcs) <= LcsLengthTreshold
                // Value of parameter should be treated as harmless only if it whole fits at one token
                || IsTreeToken(tree, lcs);
        }

        private bool IsTreeToken(CommonTree tree, string value)
        {
            if (tree.Children == null) return false;

            var isTreeToken = false;

            foreach (CommonTree child in tree.Children)
            {
                if (isTreeToken || child.Token.Text.IndexOf(value, StringComparison.Ordinal) != -1)
                {
                    return true;
                }
                isTreeToken |= IsTreeToken(child, value);
            }

            return isTreeToken;
        }

        private bool IsValidJsCode(string value, out CommonTree tree)
        {
            var lexer = new JavaScriptLexer(new ANTLRStringStream(string.Format("{0}", value)));
            var parser = new JavaScriptParser(new CommonTokenStream(lexer));
            tree = null;
            try
            {
                var program = parser.program();
                if ((parser.NumberOfSyntaxErrors == 0) &&
                    (((CommonTree)program.Tree).ChildCount > AstNodesCountTreshold) &&
                    parser.TokenStream.Count > TokensCountTreshold)
                {
                    tree = (CommonTree)program.Tree;
                    return true;
                }
            }
            // ReSharper disable EmptyGeneralCatchClause
            catch
            { }
            // ReSharper restore EmptyGeneralCatchClause
            return false;
        }

        private int LongestCommonSubstring(string str1, string str2, out string sequence)
        {
            sequence = string.Empty;
            if (String.IsNullOrEmpty(str1) || String.IsNullOrEmpty(str2))
                return 0;

            var num = new int[str1.Length, str2.Length];
            var maxlen = 0;
            var lastSubsBegin = 0;
            var sequenceBuilder = new StringBuilder();

            for (var i = 0; i < str1.Length; i++)
            {
                for (var j = 0; j < str2.Length; j++)
                {
                    if (str1[i] != str2[j])
                        num[i, j] = 0;
                    else
                    {
                        if ((i == 0) || (j == 0))
                            num[i, j] = 1;
                        else
                            num[i, j] = 1 + num[i - 1, j - 1];

                        if (num[i, j] > maxlen)
                        {
                            maxlen = num[i, j];
                            var thisSubsBegin = i - num[i, j] + 1;
                            if (lastSubsBegin == thisSubsBegin)
                            {//if the current LCS is the same as the last time this block ran
                                sequenceBuilder.Append(str1[i]);
                            }
                            else //this block resets the string builder if a different LCS is found
                            {
                                lastSubsBegin = thisSubsBegin;
                                sequenceBuilder.Length = 0; //clear it
                                sequenceBuilder.Append(str1.Substring(lastSubsBegin, (i + 1) - lastSubsBegin));
                            }
                        }
                    }
                }
            }
            sequence = sequenceBuilder.ToString();
            return maxlen;
        }
    }
}
