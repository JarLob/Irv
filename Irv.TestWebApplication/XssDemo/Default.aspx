<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Irv.TestWebApplication.XssDemo.Default" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Irv - Improved [ASP.NET] Request Validation: online demo</title>
    <script>
        function welcome() {
            var welcoming = document.getElementById('welcoming');
            welcoming.innerText = 'Welcome, <%=Request.Params["param1"]%>!';
        }
    </script>
    <%= Highlight.Include("vs") %>
</head>
<body onload="welcome()">
    <form id="form1" runat="server">
        <div id="welcoming"></div>
        <a href="<%=Request.Params["param2"]%>"><%=Request.Params["param3"]%></a>
        <div>
            <hr/><h3>Entire server-side code of this page:</h3>
            <pre><code>
&lt;%@ Page Language=&quot;C#&quot; AutoEventWireup=&quot;true&quot; CodeBehind=&quot;Default.aspx.cs&quot; Inherits=&quot;Irv.TestWebApplication.Default&quot; %&gt;

&lt;!DOCTYPE html&gt;

&lt;html xmlns=&quot;http://www.w3.org/1999/xhtml&quot;&gt;
&lt;head runat=&quot;server&quot;&gt;
    &lt;title&gt;Irv - Improved [ASP.NET] Request Validation: online demo&lt;/title&gt;
    &lt;script&gt;
        function welcome() {
            var welcoming = document.getElementById(&#39;welcoming&#39;);
            welcoming.innerText = &#39;Welcome, &lt;%=Request.Params[&quot;param1&quot;]%&gt;!&#39;;
        }
    &lt;/script&gt;
    &lt;!-- Highlight.js inclusion tag --&gt;
&lt;/head&gt;
&lt;body onload=&quot;welcome()&quot;&gt;
    &lt;form id=&quot;form1&quot; runat=&quot;server&quot;&gt;
        &lt;div id=&quot;welcoming&quot;&gt;&lt;/div&gt;
        &lt;a href=&quot;&lt;%=Request.Params[&quot;param2&quot;]%&gt;&quot;&gt;&lt;%=Request.Params[&quot;param3&quot;]%&gt;&lt;/a&gt;
        &lt;!-- Div with this code and info--&gt;
    &lt;/form&gt;
    &lt;!-- Google Analytics stuff --&gt;
&lt;/body&gt;
&lt;/html&gt;
             </code></pre><hr/>
<p>It seems to be pretty vulnerable for a few vectors of reflected XSS attacks... So, feel free to play with request parameters param1, param2 and param3.</p>
<p>Examples of validation evasion and false positives vectors or bug reports are <a href="https://github.com/kochetkov/Irv/issues">welcome</a>.</p>
        </div>
    </form>
    <script type="text/javascript">

        var _gaq = _gaq || [];
        _gaq.push(['_setAccount', 'UA-6050698-3']);
        _gaq.push(['_trackPageview']);

        (function () {
            var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
            ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
            var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
        })();

    </script>
</body>
</html>
