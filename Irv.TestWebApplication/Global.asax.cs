using System;

namespace Irv.TestWebApplication
{
    public class Global : System.Web.HttpApplication
    {
        protected void Application_BeginRequest(Object sender, EventArgs e)
        {
            Context.Items.Add("Request_Start_Time", DateTime.Now);
        }
        protected void Application_EndRequest(Object sender, EventArgs e)
        {
            var tsDuration = DateTime.Now.Subtract((DateTime)Context.Items["Request_Start_Time"]);
            Context.Response.Write("<hr><b>Request Processing Time: " + tsDuration);
        }
    }
}