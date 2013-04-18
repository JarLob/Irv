using System;

namespace Irv.TestWebApplication
{
    public partial class Default1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Response.Redirect(@"~/Demo/?param1=world&param2=http%3A%2f%2firv.c2e.pw&param3=irv.c2.pw");
        }
    }
}