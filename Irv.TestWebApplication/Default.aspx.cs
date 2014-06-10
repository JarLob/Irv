using System;

namespace Irv.TestWebApplication
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Response.Redirect(@"XssDemo/Default.aspx?param1=user&param2=http://localhost&param3=Follow%20this%20URL");
        }
    }
}