<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="index.aspx.cs" Inherits="CxQA.set.index" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <table width="400">
            <tr>
                <td>Username</td>
                <td><asp:TextBox ID="username" runat="server" width="125"/></td>
            </tr>
            <tr>
                <td>Password</td>
                <td><asp:TextBox ID="password" runat="server" TextMode="Password" width="125"/></td>
            </tr>
            <tr>
                <td> </td>
                <td><asp:Button ID="submit" runat="server" Text="Submit" OnClick="submit_click" /></td>
            </tr>
            <tr>
                <td> </td>
                <td><asp:Label ID="result" runat="server"/></td>
            </tr>
        </table>
    </form>
</body>
</html>
