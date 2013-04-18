using System.Collections.Generic;
using System.Web;
using System.Web.Util;

namespace Irv.Engine
{
    public class XssRequestValidator : RequestValidator
    {
        protected override bool IsValidRequestString(
            HttpContext context,
            string value,
            RequestValidationSource requestValidationSource,
            string collectionKey,
            out int validationFailureIndex)
        {
            validationFailureIndex = -1;
            var isAlphaNumerical = true;

            for (var i = 0; i < value.Length; i++)
            {
                // Skip harmless values belongs to [a-zA-Z0-9_]
                if ((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= 'A' && value[i] <= 'Z') ||
                    (value[i] >= '0' && value[i] <= '9') || (value[i] == '_')) continue;

                isAlphaNumerical = false;
                break;
            }

            if (!isAlphaNumerical)
            {
                // Add value to Irv.Engine.TaintfulParams request cache for further response validation
                if (!context.Items.Contains("Irv.Engine.TaintfulParams"))
                    context.Items["Irv.Engine.TaintfulParams"] = new List<RequestValidationParam>();

                ((List<RequestValidationParam>)context.Items["Irv.Engine.TaintfulParams"]).Add(
                    new RequestValidationParam(requestValidationSource.ToString(), collectionKey, value));
            }
            return true;
        }
    }
}
