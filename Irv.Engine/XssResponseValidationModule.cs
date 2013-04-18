using System.Collections.Generic;
using System.Resources;
using System.Web;

namespace Irv.Engine
{
    public class XssResponseValidationModule : IHttpModule
    {
        private readonly string _requestValidationErrorMessage =
            new ResourceManager("System.Web", new HttpRequestValidationException().GetType().Assembly).GetString(
                "Dangerous_input_detected");

        private StreamWatcher _watcher;

        public void Dispose() { }

        public void Init(HttpApplication httpApplication)
        {
            httpApplication.BeginRequest += (o, e) =>
                {
                    _watcher = new StreamWatcher(httpApplication.Response.Filter);
                    httpApplication.Response.Filter = _watcher;
                };

            httpApplication.EndRequest += (o, e) =>
                {
                    // Only 'text/html' content type of response supported as yet
                    if (!httpApplication.Context.Response.ContentType.StartsWith("text/html")) return;
                    // TODO: Add support of 'application/json' and 'text/xml' MIME types

                    var xssResponseValidator = new HtmlResponseValidator();
                    RequestValidationParam dangerousParam;

                    if (httpApplication.Context.Items.Contains("Irv.Engine.TaintfulParams") &&
                        !xssResponseValidator.IsValidHtmlResponseString(
                            (List<RequestValidationParam>) httpApplication.Context.Items["Irv.Engine.TaintfulParams"],
                            _watcher.ToString(),
                            out dangerousParam))
                    {
                        throw new HttpRequestValidationException(
                            string.Format(
                                _requestValidationErrorMessage, dangerousParam.Source,
                                string.Format("{0}=\"{1}\"...", dangerousParam.CollectionKey, dangerousParam.Value.Length > 15 ? dangerousParam.Value.Substring(0, 15) : dangerousParam.Value)));
                    }
                };
        }
    }
}