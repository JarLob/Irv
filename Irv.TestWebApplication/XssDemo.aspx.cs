using System;

namespace Irv.TestWebApplication
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (IsPostBack) return;

            if (string.IsNullOrEmpty(Request.Params["param1"]) 
                && string.IsNullOrEmpty(Request.Params["param2"]) 
                && string.IsNullOrEmpty(Request.Params["param2"]))
            {
                Response.Redirect(@"?param1=user&param2=http://localhost&param3=Follow%20this%20URL");
            }
        }
    }
}