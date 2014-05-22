using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

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
                Response.Redirect(@"Default.aspx?param1=user&param2=http://localhost&param3=Follow%20this%20URL");
            }
        }
    }
}