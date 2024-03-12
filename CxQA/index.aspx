<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="index.aspx.cs" Inherits="CxQA.Index" EnableEventValidation="false" Async="true" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Checkmarx Scan Comparison</title>
    <link rel="stylesheet" runat="server" media="screen" href="resources/stylesheets/cxgate.css" />
    <!-- This script is needed to ensure only one radio button can be selected in the scans dropdowns -->
    <script type="text/javascript">
    function SetUniqueRadioButton(nameregex, current) {
        for (var i = 0; i < document.forms[0].elements.length; i++) {
            var e = document.forms[0].elements[i];
            if (e.type == 'radio' && e.name.match(nameregex)) {
                e.checked = false;
            }
        }
        current.checked = true;
    }
    </script>

</head>

<body>
    <div class="leftPanel" />
    <div class="mainPanel" align="center" width="900px">
        <form id="form1" runat="server">
            <br />
            <table border="0" align="center" width="900px" runat="server" id="mainTable">
                <tr>
                    <td>
                        <img src="resources/images/logo.png" width="150" height="20" />
                        <br />
                        <b>CxGate v<asp:Label runat="server" ID="cxGateVersion" /></b>
                        <p />
                    </td>
                    <td>
                        <div runat="server" id="divAccountInfo" visible="false" style="display: grid; justify-content: right; align-items: end;">
                            <asp:Label runat="server" ID="loggedInUser" align="right" />
                            <br />
                            <asp:Button runat="server" ID="logout" Text="Logout" OnClick="UI_EventRouter" />
                        </div>
                    </td>
                </tr>
                <tr>
                    <td colspan="2">

                        <div runat="server" id="divErrorMessage" visible="false" style="display: grid; justify-content: center; align-items: center;">
                            <p class="error">
                                <asp:Label runat="server" ID="errorMessage" /></p>
                        </div>

                        <div runat="server" id="divMessageText" visible="false" style="display: grid; justify-content: center; align-items: center;">
                            <p class="message">
                                <asp:Label runat="server" ID="messageText" /></p>
                        </div>

                        <div runat="server" id="divLoginForm" visible="true" style="margin: 20px auto; display: grid; justify-content: center; align-items: center;">
                            <table border="0" width="400px">
                                <tr>
                                    <td>&nbsp;</td>
                                    <td>&nbsp;</td>
                                </tr>
                                <tr>
                                    <td><strong>Domain</strong></td>
                                    <td>
                                        <asp:DropDownList runat="server" ID="authDomainsDropDown" /></td>
                                </tr>
                                <tr>
                                    <td><strong>Username</strong></td>
                                    <td>
                                        <asp:TextBox runat="server" ID="user" Text="admin@cx" /></td>
                                </tr>
                                <tr>
                                    <td><strong>Password</strong></td>
                                    <td>
                                        <asp:TextBox runat="server" ID="pass" Text="" TextMode="Password" /></td>
                                </tr>
                                <tr>
                                    <td>&nbsp;</td>
                                    <td>
                                        <asp:Button runat="server" ID="login" Text="Login" OnClick="UI_EventRouter" /></td>
                                </tr>
                                <tr>
                                    <td>&nbsp;</td>
                                    <td>&nbsp;</td>
                                </tr>
                                <tr>
                                    <td>&nbsp;</td>
                                    <td>&nbsp;</td>
                                </tr>
                            </table>
                        </div>

                        <div runat="server" id="divProjectsForm" visible="false">
                            <br />
                            <table width="100%">
                                <tr>
                                    <td width="50%" align="left"><b>Run CxGate Report</b></td>
                                    <!--<td width="50%" align="left" runat="server" id="details_lbl"><b>Vulnerability Details Report</b></td>-->
                                </tr>
                                <tr>
                                    <td align="left">
                                        <asp:DropDownList runat="server" ID="project_list" OnSelectedIndexChanged="UI_EventRouter" AutoPostBack="true" /></td>
                                    <!--<td runat="server" id="details_select" align="left" width="85%">
                                        <asp:DropDownList runat="server" ID="projectsTeamsList" OnSelectedIndexChanged="UI_EventRouter" AutoPostBack="true" /></td>-->
                                </tr>
                            </table>
                            <br />
                        </div>

                        <div runat="server" id="divScansForm" visible="false">
                            <strong>
                                <p style="color: forestgreen;">1.  Select the latest PRD scan.</p>
                            </strong>
                            <div class="withScroll">
                                <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="prd_latest" AutoGenerateColumns="false" CellPadding="4" OnRowDataBound="prod_scans_RowDataBound" CssClass="scanList">
                                    <Columns>
                                        <asp:TemplateField HeaderText="Compare">
                                            <ItemTemplate>
                                                <asp:RadioButton ID="RadioButtonComparePrd" runat="server" GroupName="CompareGroupPrd" 
                                                    Checked='<%# Convert.ToBoolean(Eval("Compare")) %>' onClick="SetUniqueRadioButton(/CompareGroupPrd$/, this)" />
                                            </ItemTemplate>
                                        </asp:TemplateField>
                                        <asp:BoundField DataField="Project" HeaderText="Project" />
                                        <asp:BoundField DataField="Scan ID" HeaderText="Scan ID" />
                                        <asp:BoundField DataField="Scan Origin" HeaderText="Scan Origin" />
                                        <asp:BoundField DataField="Is Incremental" HeaderText="Is Incremental" />
                                        <asp:BoundField DataField="Scan Finished" HeaderText="Scan Finished" />
                                        <asp:BoundField DataField="Comments" HeaderText="Comments" />
                                        <asp:BoundField DataField="Locked" HeaderText="Locked" />
                                    </Columns>
                                </asp:GridView>
                            </div>
                            <br />
                            <br />
                            <strong>
                                <p style="color: forestgreen;">2.  Select a scan from DEV that you wish to compare.</p>
                            </strong>
                            <div class="withScroll">
                                <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="project_scans" AutoGenerateColumns="false" CellPadding="4" OnRowDataBound="project_scans_RowDataBound" CssClass="scanList">
                                    <Columns>
                                        <asp:TemplateField HeaderText="Compare">
                                            <ItemTemplate>
                                                <asp:RadioButton ID="RadioButtonCompareDev" runat="server" GroupName="CompareGroupDev" 
                                                    Checked='<%# Convert.ToBoolean(Eval("Compare")) %>' onClick="SetUniqueRadioButton(/CompareGroupDev$/, this)" />
                                            </ItemTemplate>
                                        </asp:TemplateField>
                                        <asp:BoundField DataField="Project" HeaderText="Project" />
                                        <asp:BoundField DataField="Scan ID" HeaderText="Scan ID" />
                                        <asp:BoundField DataField="Scan Origin" HeaderText="Scan Origin" />
                                        <asp:BoundField DataField="Is Incremental" HeaderText="Is Incremental" />
                                        <asp:BoundField DataField="Scan Finished" HeaderText="Scan Finished" />
                                        <asp:BoundField DataField="Comments" HeaderText="Comments" />
                                        <asp:BoundField DataField="Locked" HeaderText="Locked" />
                                    </Columns>
                                </asp:GridView>
                            </div>
                            <br />
                            <strong>
                                <p style="color: forestgreen;">3.  Click to compare the two scans.</p>
                            </strong>
                            <asp:Button ID="compare" Visible="false" runat="server" Text="Compare Scans" OnClick="UI_EventRouter" />
                        </div>

                        <div runat="server" id="divComparisonForm" visible="false">
                            <asp:Button runat="server" ID="pdf" Text="Get Report Link" Visible=" false" OnClick="UI_EventRouter" />
                            <asp:Button ID="listScans" Visible="true" runat="server" Text="Go Back" OnClick="UI_EventRouter" />
                            <asp:CheckBox runat="server" ID="includeLowsInfoInReport" AutoPostBack="true" OnCheckedChanged="UI_EventRouter" Text="Include low and informational results" />
                            <br />
                            <br />
                            <asp:Panel runat="server" ID="ScanComparePanel">
                                <div>
                                    <b>Scan Comparison</b>
                                    <p />
                                    <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="comparison" AutoGenerateColumns="true" CellPadding="4" CssClass="compareTable" />
                                    <br />
                                    <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="not_exploitable" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="not_exploitable_RowDataBound" />
                                    <br />
                                    <asp:GridView HeaderStyle-BackColor="White" RowStyle-BackColor="White" runat="server" ID="counts" AutoGenerateColumns="true" CellPadding="4" OnRowDataBound="counts_RowDataBound" />
                                </div>
                            </asp:Panel>
                            <p />
                        </div>

                        <div runat="server" id="divReportUrl" visible="false">
                            <asp:Label runat="server" ID="url" />
                        </div>
                    </td>
                </tr>
            </table>
        </form>
    </div>
    <div class="rightPanel" />
    <p />
    <p />
    <div runat="server" id="divFooter" visible="false" class="footer">
        <p />
        <i>Works best with Chrome and Firefox.</i>
    </div>
</body>



</html>
