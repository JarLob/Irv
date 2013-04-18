using System;
using System.Net;
using System.Web;
using System.Web.UI;

namespace Irv.TestWebApplication
{
    public partial class Error : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            Response.Clear();

			var lastError = Server.GetLastError();
            if (lastError != null)
            {
                message.Text = HttpUtility.HtmlEncode(((lastError is HttpException) && (lastError.InnerException != null) ? lastError.InnerException : lastError).Message);
            }
        }
    }
}