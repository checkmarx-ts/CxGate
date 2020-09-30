<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="index.aspx.cs" Inherits="CxQA.index" EnableEventValidation="false" Async="true" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Checkmarx Scan Comparison</title>

<style>
<!--
    body {
    background-image: url(Checkmarx_920.jpg);
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-position: right,center;
    }
    //-->
</style>
</head>
<body>
    <form id="form1" runat="server">
        <div runat="server" id="login_form" visible="true" style="display:flex;justify-content:center;align-items:center"> 
            <table>
                <tr><td>&nbsp;</td><td>&nbsp;</td></tr>
                <tr><td>&nbsp;</td><td>&nbsp;</td></tr>
                <tr><td>&nbsp;</td><td>&nbsp;</td></tr>
                <tr><td>&nbsp;</td><td>&nbsp;</td></tr>
                <tr><td>&nbsp;</td><td>&nbsp;</td></tr>
                <tr><td><strong>domain</strong></td><td><asp:DropDownList runat="server" ID="codomain"/></td></tr>
                <tr><td><strong>username</strong></td><td><asp:TextBox runat="server" ID="user" Text="admin@cx"/></td></tr>
                <tr><td><strong>password</strong></td><td><asp:TextBox runat="server" ID="pass" Text="" TextMode="Password" /></td></tr>
                <tr><td>&nbsp;</td><td><asp:Button runat="server" ID="login" Text="Login" OnClick="login_Click" /></td></tr>
                <tr><td>&nbsp;</td><td colspan="2"><asp:Label runat="server" ID="loginerror" /></td></tr>
                </table>
        </div>

        <div runat="server" id="projects_form" visible="false" >
            <table>
                <tr>
                    <td>Run CxGate Report:</td>
                    <td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>
                    <td runat="server" id="details_lbl">Vulnerability Details Report:</td>
                </tr>
                <tr>
                    <td width="15%" align="left"> <asp:DropDownList runat="server" ID="project_list" OnSelectedIndexChanged="projects_SelectedIndexChanged" AutoPostBack="true" /></td>
                    <td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>
                    <td runat="server" id="details_select" align="left" width="85%"><asp:DropDownList runat="server" ID="extract_param" OnSelectedIndexChanged="extract_param_SelectedIndexChanged" AutoPostBack="true" /></td>
                </tr>
                </table>
            <hr />
        </div>

        <div runat="server" id="alert" visible="false">
            <asp:Label runat="server" ID="message" />
        </div>

        <div runat="server" id="scans_form" visible="false" >
            <asp:Label runat="server" ID="error" ForeColor="Red" />
            <br />
            <strong><p style="color:forestgreen;">1.  Select the latest scan from either the production or QA project.</p></strong>
            <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="prd_latest" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="prod_scans_RowDataBound" /><br />
            
            <br />
            <strong><p style="color:forestgreen;">2.  Select a scan from the dev project you wish to compare.</p></strong>
            <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="project_scans" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="project_scans_RowDataBound" />

            <br />
            <strong><p style="color:forestgreen;">3.  Click to compare the two scans.</p></strong>
            <asp:Button ID="compare" Visible="false" runat="server" Text="Compare Scans" OnClick="compare_Click" /> 
        </div>
        <div runat="server" id="comparison_form" visible="false">
            <asp:Button runat="server" ID="pdf" Text="Get Report Link"  Visible=" false" OnClick="pdf_Click" /> <asp:Button ID="goBack" Visible="true" runat="server" Text="Go Back" OnClick="goBack_Click" /> <asp:CheckBox runat="server" ID="lows" AutoPostBack="true" OnCheckedChanged="compare_Click" Text="Include low and informational results" />
            <br /><br />
            <asp:Panel runat="server" ID="panel">
                <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="comparison" AutoGenerateColumns="true" CellPadding="4" />
                <br />
                <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="counts" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="counts_RowDataBound" />
                <br />
                <asp:GridView HeaderStyle-BackColor="White"  RowStyle-BackColor="White" runat="server" ID="not_exploitable" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="not_exploitable_RowDataBound" />
            </asp:Panel>
        </div>
        <div runat="server" id="report_url" visible="false">
            <asp:Label runat="server" ID="url" />
        </div>
    </form>
</body>



</html>
