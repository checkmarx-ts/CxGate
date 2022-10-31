using CredentialManagement;
using CxQA.CX;
using Newtonsoft.Json.Linq;
using OfficeOpenXml.FormulaParsing.LexicalAnalysis;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;
using System.Web.UI;
using System.Web.UI.WebControls;
using TheArtOfDev.HtmlRenderer.Core;
using TheArtOfDev.HtmlRenderer.PdfSharp;
using ListItem = System.Web.UI.WebControls.ListItem;

namespace CxQA
{
    public enum CxGateOp
    {
        LIST_PROJECTS,
        LIST_SCANS,
        COMPARE_SCANS,
        GENERATE_REPORT
    }

    public struct CxGateViewStateKeys
    {
        public static readonly string TOKEN = "cx_token";
        public static readonly string SOAP_TOKEN = "cx_soap_token";

        public static readonly string USERNAME = "cx_user";
        public static readonly string FIRST_NAME = "cx_first_name";
        public static readonly string LAST_NAME = "cx_last_name";
        public static readonly string USER_EMAIL = "cx_user_email";

        public static readonly string CUSTOM_FIELDS = "cx_custom_fields";
        public static readonly string CURRENT_OP = "cx_current_op";
    }

    public class CxGateConfig
    {
        public bool isInitialized = false;

        //--CxGate Settings--//
        public String cxserver;
        public String domain;
        public int pageWidthInPixels;
        public String pageSize;
        public int baselineScanAge;
        public int devScanAge;
        public String commentsFilterRegEx;

        //--Details Report-- set to false if problems with SMTP setup/
        public bool showDetailsReport;

        //--SMTP Settings--//
        public String smtpHost;
        public int smtpPort;
        public String sendFrom;
        public bool defaultCred;
        public bool enableSSL;

        //--if defaultCred is false, these should be configured--/
        public String smtpUsername;
        public String smtpPassword;

        //--set to true to show advanced debugging entries in the log--/
        public bool debug = false;
    }

    public partial class Index : System.Web.UI.Page
    {
        #region Variable declarations
        private static readonly String VERSION = "3.02";
        private CxGateConfig config = new CxGateConfig();
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly String baseline_suffix_p = "_PRD";
        private static readonly String baseline_suffix_q = "_QA";
        private bool ignoreFilter = false;
        private String jwtToken = String.Empty;
        List<queryName> queryNames = new List<queryName>();
        #endregion

        public Index()
        {
            log4net.Config.XmlConfigurator.Configure(new FileInfo(Server.MapPath("~/log4net.config")));
        }
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);

            Response.Cache.SetCacheability(System.Web.HttpCacheability.NoCache);
            Response.Cache.SetNoStore();
            Response.Cache.SetAllowResponseInBrowserHistory(false);
            Response.Cache.SetExpires(DateTime.Now);
            Response.Cache.SetValidUntilExpires(true);
        }

        private void LoadConfig(CxGateConfig config)
        {
            // if (config.debug) log.Debug("-------->>> LoadConfig");

            log.Info("Loading CxGate configuration.");

            try { config.cxserver = getProperty("cxserver"); } catch { config.cxserver = null; }
            try { config.domain = getProperty("domain"); } catch { config.domain = null; }
            try { config.debug = Boolean.Parse(getProperty("debug")); } catch { config.debug = false; }
            try { config.showDetailsReport = Boolean.Parse(getProperty("showDetailsReport")); } catch { config.showDetailsReport = false; }
            try { config.pageWidthInPixels = Int32.Parse(getProperty("pagewidthinpixels")); } catch { config.pageWidthInPixels = 1000; }
            try { config.pageSize = getProperty("pagesize"); } catch { config.pageSize = "legal"; }
            try { config.baselineScanAge = Int32.Parse(getProperty("baselineScanAge")); } catch { config.baselineScanAge = 0; }
            try { config.devScanAge = Int32.Parse(getProperty("devScanAge")); } catch { config.devScanAge = 0; }
            try { config.commentsFilterRegEx = getProperty("commentsFilterRegEx"); } catch { config.commentsFilterRegEx = @"^[; ]+$|(no code changes)"; }

            ignoreFilter = String.IsNullOrEmpty(config.commentsFilterRegEx);
            if (ignoreFilter)
                log.Debug("Filter regex for comments was empty in config. Ignoring comment filters.");


            // Minimum configuration required
            config.isInitialized = !String.IsNullOrEmpty(config.cxserver);

        }

        protected void Page_Load(object sender, EventArgs e)
        {
            // Read config if it hasn't been loaded yet
            if (!config.isInitialized) LoadConfig(config);

            // if (config.debug) log.Debug("=============================== >>>>>>>>> Page_Load");

            ShowHeader();
            ClearAllMessages();
            HideBody();

            if (ViewState[CxGateViewStateKeys.TOKEN] == null)
            {
                if (!IsPostBack)
                {
                    if (authDomainsDropDown.Items.Count == 0)
                        PopulateDomainDropDown();
                    ShowLoginForm();
                }
            }
            else
            {
                ShowDivs();
            }
        }

        private void PopulateDomainDropDown()
        {
            // if (config.debug) log.Debug("-------->>> PopulateDomainDropDown");

            // Populate the drop down 
            authDomainsDropDown.Items.Clear();
            authDomainsDropDown.Items.Add("Application");
            if (!String.IsNullOrEmpty(config.domain))
                authDomainsDropDown.Items.Add(config.domain.ToUpper());
            else
                log.Warn("No domain was found in the config file. Using Application authentication only.");
        }

        #region ViewState
        private bool IsAuthenticated()
        {
            bool isAuth = ViewState != null && ViewState[CxGateViewStateKeys.TOKEN] != null;
            // if (config.debug) log.Debug("-------->>> IsAuthenticated : " + isAuth);
            return isAuth;
        }
        #endregion

        private void ShowDivs()
        {
            // if (config.debug) log.Debug("-------->>> ShowDivs");

            CxGateOp op = (CxGateOp)ViewState[CxGateViewStateKeys.CURRENT_OP];
            if (config.debug) log.Debug("Current operation in ViewState is [" + op + "]");

            switch (op)
            {
                default:
                case CxGateOp.LIST_PROJECTS:
                    Get_Projects();
                    if (config.showDetailsReport) GetProjectsAndTeams();
                    break;
                case CxGateOp.COMPARE_SCANS:
                    ShowComparisonForm();
                    break;
                case CxGateOp.GENERATE_REPORT:
                    // NOP for now
                    break;
            }

            // Always show project form if logged in
            ShowProjectsForm(config.showDetailsReport);

            try
            {
                string projectname = Request.QueryString["project"];
                if (!String.IsNullOrEmpty(projectname)) CompareScansForProject(projectname);
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Could not compare scans for requested project.<br>" + ex.Message);
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }


        #region UI Click Handlers

        protected async void UI_EventRouter(object sender, EventArgs e)
        {

            if (typeof(WebControl).IsAssignableFrom(sender.GetType()))
            {
                WebControl source = (WebControl)sender;
                try
                {
                    if (IsAuthenticated())
                    {
                        String refreshToken = ViewState[CxGateViewStateKeys.TOKEN].ToString();
                        jwtToken = await getJWT(refreshToken);
                    }

                    switch (source.ID)
                    {
                        case "login":
                            await Login(); break;
                        case "logout":
                            await Logout(); break;
                        case "includeLowsInfoInReport":
                        case "compare":
                            await CompareScans(); break;
                        case "listScans":
                        case "project_list":
                            await ListScans(); break;
                        case "pdf":
                            await GenerateComparisonReport(); break;
                        case "projectsTeamsList":
                            await GenerateAndEmailDetailsReport(); break;
                    }

                    if (IsAuthenticated())
                    {
                        ShowDivs();
                    }
                }
                catch (Exception ex)
                {
                    ShowErrorMessage("A fatal error occurred." + ex.StackTrace);
                }
            }
        }
        protected async Task Login()
        {
            // if (config.debug) log.Debug("-------->>> Login");

            String username = String.Empty;
            try
            {
                // If we're logging in, and we have an existing ViewState
                if (!IsAuthenticated())
                {
                    ViewState.Clear();
                }

                ClearAllMessages();

                if (authDomainsDropDown.Text.Equals("Application"))
                    username = user.Text;
                else
                    username = authDomainsDropDown.Text + "\\" + user.Text;

                // Default landing operation
                ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.LIST_PROJECTS);

                String refreshToken = await getAuthToken(username, pass.Text);

                ViewState.Add(CxGateViewStateKeys.USERNAME, username);
                ViewState.Add(CxGateViewStateKeys.TOKEN, refreshToken);
                // TODO: REMOVE
                ViewState.Add(CxGateViewStateKeys.SOAP_TOKEN, String.Empty);

                String userProfileJson = String.Empty;
                String email = String.Empty;
                String firstName = "Error";
                String lastName = "Error";
                try
                {
                    if (IsAuthenticated())
                    {
                        jwtToken = await getJWT(refreshToken);
                    }

                    userProfileJson = await getLoggedInProfile();
                    dynamic t = JObject.Parse(userProfileJson);

                    email = t.email.ToString();
                    firstName = t.firstName.ToString();
                    lastName = t.lastName.ToString();

                    ViewState.Add(CxGateViewStateKeys.USER_EMAIL, email);
                    ViewState.Add(CxGateViewStateKeys.FIRST_NAME, firstName);
                    ViewState.Add(CxGateViewStateKeys.LAST_NAME, lastName);

                    if (config.debug) log.Debug("Email address of requester:  " + email);
                }
                catch (Exception exx)
                {
                    log.Error("Could not get profile information (name, e-mail address) of logged in user:  " + userProfileJson + Environment.NewLine + exx.StackTrace);
                }

                // Succesful login
                String userFirstLastName = !String.IsNullOrEmpty(firstName) || !String.IsNullOrEmpty(lastName) ? (lastName + ", " + firstName) : "";
                loggedInUser.Text = userFirstLastName + "<br/>(" + username + ")";
                divAccountInfo.Visible = true;
                log.Info(user.Text + " logged in.");

            }
            catch (Exception ex)
            {
                log.Error(username + " could not log in:  " + ex.Message + " - " + ex.StackTrace);
                ShowErrorMessage("Could not log in as " + username + ".  Please try again.");
            }
        }
        protected async Task Logout()
        {
            // if (config.debug) log.Debug("-------->>> logout_Click");

            if (!IsAuthenticated())
            {
                log.Debug("ViewState does not contain user data. Nothing to logout. Redirecting to login page.");
                Response.Redirect("index.aspx", false);
                return;
            }

            String user = ViewState[CxGateViewStateKeys.USERNAME].ToString();
            String token = ViewState[CxGateViewStateKeys.TOKEN].ToString();

            log.Debug("Attempting to logout user " + user);

            HttpClient client = new HttpClient();
            String url = config.cxserver + "/cxrestapi/auth/identity/connect/revocation";
            var values = new Dictionary<string, string>
                {
                    { "token_type_hint", "refresh_token" },
                    { "token", token },
                    { "client_id", "resource_owner_sast_client" },
                    { "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" }
                };

            var content = new FormUrlEncodedContent(values);
            var response = await client.PostAsync(url, content);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                log.Info("User [" + user + "]'s token was logged out on the server.");

                ViewState[CxGateViewStateKeys.USERNAME] = null;
                ViewState[CxGateViewStateKeys.TOKEN] = null;
                jwtToken = null;
                if (config.debug) log.Debug("User state has been cleared.");

                Response.Redirect("index.aspx", false);
                return;
            }
            else
            {
                log.Error("Could not log out user [" + user + "]. " + response.ReasonPhrase);
            }
        }
        protected async Task CompareScans()
        {
            // if (config.debug) log.Debug("-------->>> CompareScans");

            ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.COMPARE_SCANS);

            int checked_count = 0;
            bool noscanrun = false;
            string[] scanIDs = new String[2];
            DateTime baseline = new DateTime();
            DateTime dev = new DateTime();

            foreach (GridViewRow row in prd_latest.Rows)
            {
                CheckBox cb = (CheckBox)row.Cells[0].Controls[0];
                if (cb.Checked)
                {
                    baseline = DateTime.Parse(row.Cells[5].Text);
                    scanIDs[0] = row.Cells[2].Text.ToString();
                    checked_count++;
                }
            }

            foreach (GridViewRow row in project_scans.Rows)
            {
                CheckBox cb = (CheckBox)row.Cells[0].Controls[0];
                if (cb.Checked)
                {
                    if (row.Cells[5].Text.ToString().Equals("N/A"))
                        noscanrun = true;
                    else
                        dev = Convert.ToDateTime(row.Cells[5].Text);

                    scanIDs[1] = row.Cells[2].Text.ToString();
                    checked_count++;
                }
            }

            String errMsg = String.Empty;
            if (checked_count != 2 || scanIDs[0] == null || scanIDs[1] == null)
            {
                errMsg = "Please select one PRD/QA and one DEV scans to compare.";
            }
            else if (noscanrun)
            {
                errMsg = "Only production scans skipped due to no code changes detected are allowed.<br>Please select a different development scan for comparison.";
            }
            else if (DateTime.Compare(baseline, dev) > 0)
            {
                errMsg = "The baseline scan must be older than the development scan.<br>Please choose a different baseline scan or run a new development scan.";
            }
            else
            {
                ClearErrorMessage();
                getComparison(scanIDs);
                pdf.Visible = true;
            }

            if (!String.IsNullOrEmpty(errMsg))
            {
                getScans();
                ShowMessage(errMsg);
            }
        }
        protected async Task GenerateComparisonReport()
        {
            // if (config.debug) log.Debug("-------->>> GenerateComparisonReport");

            // Current op
            ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.GENERATE_REPORT);

            try
            {
                createPDFAndLink();
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Could not create comparison report (PDF).<br/>" + ex.Message);
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }
        protected async Task ListScans()
        {
            // if (config.debug) log.Debug("-------->>> ListScans");

            // Current op
            ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.LIST_SCANS);

            getScans();
        }
        #endregion

        #region UI Visibility Controls
        private void ClearAllMessages()
        {
            // if (config.debug) log.Debug("-------->>> ClearAllMessages");

            ClearErrorMessage();
            ClearMessage();
        }
        private void HideBody()
        {
            // if (config.debug) log.Debug("-------->>> HideBody");

            HideAllForms();
            divFooter.Visible = false;
        }

        private void HideAllForms()
        {
            // if (config.debug) log.Debug("-------->>> HideAllForms");

            divComparisonForm.Visible = false;
            divProjectsForm.Visible = false;
            divReportUrl.Visible = false;
            divScansForm.Visible = false;
        }
        private void ShowHeader()
        {
            // if (config.debug) log.Debug("-------->>> ShowHeader");

            this.Title = "CxGate " + VERSION;
            cxGateVersion.Text = VERSION;
        }
        private void ShowProjectsForm(bool showDetails)
        {
            // if (config.debug) log.Debug("-------->>> ShowProjectsForm");

            divLoginForm.Visible = false;
            divProjectsForm.Visible = true;

            details_lbl.Visible = showDetails;
            details_select.Visible = showDetails;
        }

        private void ShowComparisonForm()
        {
            // if (config.debug) log.Debug("-------->>> ShowComparisonForm");
            divComparisonForm.Visible = true;
        }
        private void ShowScansForm()
        {
            // if (config.debug) log.Debug("-------->>> ShowScansForm");
            divScansForm.Visible = true;
        }

        private void ShowLoginForm()
        {
            // if (config.debug) log.Debug("-------->>> ShowLoginForm");
            divLoginForm.Visible = true;
            divProjectsForm.Visible = false;
            divFooter.Visible = true;
        }
        private void ClearMessage()
        {
            // if (config.debug) log.Debug("-------->>> ClearMessage");
            divMessageText.Visible = false;
            messageText.Text = "";
        }
        private void ShowMessage(String message)
        {
            // if (config.debug) log.Debug("-------->>> ShowMessage");
            divMessageText.Visible = true;
            messageText.Text = message;
        }
        private void ClearErrorMessage()
        {
            // if (config.debug) log.Debug("-------->>> ClearErrorMessage");
            errorMessage.Text = "";
            divErrorMessage.Visible = false;
        }
        private void ShowErrorMessage(String message)
        {
            // if (config.debug) log.Debug("-------->>> ShowErrorMessage");
            errorMessage.Text = message;
            divErrorMessage.Visible = true;
        }
        #endregion

        #region Project Data
        private void Get_Projects()
        {
            // if (config.debug) log.Debug("-------->>> Get_Projects");

            if (project_list.Items.Count > 0) return;

            try
            {

                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx";

                CxWSResponseProjectScannedDisplayData projects = SOAPservice.GetProjectScannedDisplayData("");

                if (projects.IsSuccesfull)
                {
                    foreach (ProjectScannedDisplayData p in projects.ProjectScannedList)
                    {
                        if (p.ProjectName.ToString().ToLower().Contains("_dev"))
                            project_list.Items.Add(new ListItem(p.ProjectName.ToString(), p.ProjectID.ToString()));
                    }

                    // Sort first, and then add the 'Select a project or...' entry at the top
                    SortListControl(project_list, true);
                    project_list.Items.Insert(0, new ListItem("Select a project...", "-1"));

                }
                else
                {
                    ShowErrorMessage("Could not fetch project data from server.<br/>" + projects.ErrorMessage);
                    log.Error(projects.ErrorMessage);
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch project data from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }
        private void GetProjectsAndTeams()
        {
            // if (config.debug) log.Debug("-------->>> GetProjectsAndTeams");
            if (projectsTeamsList.Items.Count > 0) return;

            List<string> tlist = new List<string>();
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectsDisplayData projects = SOAPservice.GetProjectsDisplayData(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString());
                foreach (ProjectDisplayData p in projects.projectList)
                {
                    if (!tlist.Contains(p.Group + "\\" + p.ProjectName))
                    {
                        tlist.Add(p.Group + "\\" + p.ProjectName);
                        projectsTeamsList.Items.Add(new ListItem(p.Group + "\\" + p.ProjectName, p.projectID.ToString()));
                    }

                    if (!tlist.Contains(p.Group))
                    {
                        tlist.Add(p.Group);
                        projectsTeamsList.Items.Insert(tlist.Count - 1, new ListItem(p.Group, p.Group.ToString()));
                    }
                }

                // Sort first, and then add the 'Select a project or...' entry at the top
                SortListControl(projectsTeamsList, true);
                projectsTeamsList.Items.Insert(0, new ListItem("Select a project or team...", "-1"));

            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch project/team data from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }
        private void Get_Project_Properties(long pid)
        {
            // if (config.debug) log.Debug("-------->>> Get_Project_Properties");
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponsProjectProperties properties = SOAPservice.GetProjectProperties(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), pid, ScanType.UNKNOWN);
                string values = "";
                for (int i = 0; i < properties.ProjectConfig.ProjectConfig.CustomFields.Length; i++)
                    values += properties.ProjectConfig.ProjectConfig.CustomFields[i].Value + " ";

                ViewState[CxGateViewStateKeys.CUSTOM_FIELDS] = values;
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }
        #endregion

        #region Scan Data
        private string[] Get_LastScan(String projectname)
        {
            // if (config.debug) log.Debug("-------->>> Get_LastScan");
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectScannedDisplayData projects = SOAPservice.GetProjectScannedDisplayData(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString());
                foreach (ProjectScannedDisplayData p in projects.ProjectScannedList)
                {
                    if (p.ProjectName.ToString().ToLower().Equals(projectname.ToLower()))
                    {
                        return new string[] { p.LastScanID.ToString(), p.ProjectName, p.ProjectID.ToString() };
                    }
                }
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }

            return null;
        }
        private void getScans()
        {
            // if (config.debug) log.Debug("-------->>> getScans");

            ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.LIST_SCANS);
            if (project_list.SelectedItem.Value.Equals("-1")) return;

            ClearScansGridView();

            String projectName = project_list.SelectedItem.Text;

            log.Info(projectName + " selected by " + ViewState[CxGateViewStateKeys.USERNAME]);
            divComparisonForm.Visible = false;

            string[] p_prd = null;
            try { p_prd = getBaselineScan(projectName, baseline_suffix_p); }
            catch { p_prd = null; }

            string[] p_qa = null;
            try { p_qa = getBaselineScan(projectName, baseline_suffix_q); }
            catch { p_qa = null; }

            if (project_list.SelectedIndex != 0 && (p_prd != null || p_qa != null))
            {
                ClearErrorMessage();
                divScansForm.Visible = true;

                DataTable dt = new DataTable();
                dt.Columns.Add("Compare", typeof(bool));
                dt.Columns.Add("Project", typeof(string));
                dt.Columns.Add("Scan ID", typeof(string));
                dt.Columns.Add("Scan Origin", typeof(string));
                dt.Columns.Add("Is Incremental", typeof(bool));
                dt.Columns.Add("Scan Finished", typeof(string));
                dt.Columns.Add("Comments", typeof(string));
                dt.Columns.Add("Locked", typeof(bool));

                DataTable dtp = new DataTable();
                dtp.Columns.Add("Compare", typeof(bool));
                dtp.Columns.Add("Project", typeof(string));
                dtp.Columns.Add("Scan ID", typeof(string));
                dtp.Columns.Add("Scan Origin", typeof(string));
                dtp.Columns.Add("Is Incremental", typeof(bool));
                dtp.Columns.Add("Scan Finished", typeof(string));
                dtp.Columns.Add("Comments", typeof(string));
                dtp.Columns.Add("Locked", typeof(bool));

                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                    SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                    Regex regex = new Regex(config.commentsFilterRegEx);
                    log.Info("Comment filtering pattern applied to scans: [" + config.commentsFilterRegEx + "]");

                    Get_Project_Properties(Int64.Parse(project_list.SelectedItem.Value));
                    CxWSResponseScansDisplayData sdd = SOAPservice.GetScansDisplayData(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), Int64.Parse(project_list.SelectedItem.Value));
                    if (sdd != null)
                    {
                        foreach (ScanDisplayData s in sdd.ScanList)
                        {
                            string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                            if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * config.devScanAge)) > 0 || config.devScanAge == 0)
                            {
                                Match match = regex.Match(s.Comments.ToString());
                                if ((!match.Success || ignoreFilter) && !s.IsIncremental)
                                {
                                    dt.Rows.Add(false, projectName, s.ScanID.ToString(), s.Origin.ToString(), s.IsIncremental, getEngineFinishTime(s.ScanID), s.Comments.ToString(), s.IsLocked);
                                }
                            }
                        }
                    }

                    if (p_prd != null)
                    {
                        sdd = SOAPservice.GetScansDisplayData(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), Int64.Parse(p_prd[2]));
                        if (sdd != null)
                        {
                            foreach (ScanDisplayData s in sdd.ScanList)
                            {
                                string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                    " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                                if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * config.baselineScanAge)) > 0 || config.baselineScanAge == 0)
                                {
                                    Match match = regex.Match(s.Comments.ToString());
                                    if (!match.Success || true /*ignoreFilter*/)
                                    {
                                        dtp.Rows.Add(false, p_prd[1], s.ScanID.ToString(), s.Origin.ToString(), s.IsIncremental, datetime, s.Comments.ToString(), s.IsLocked);
                                    }
                                }
                            }
                        }
                    }

                    if (p_qa != null)
                    {
                        sdd = SOAPservice.GetScansDisplayData(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), Int64.Parse(p_qa[2]));
                        if (sdd != null)
                        {
                            foreach (ScanDisplayData s in sdd.ScanList)
                            {
                                string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                    " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                                if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * config.baselineScanAge)) > 0 || config.baselineScanAge == 0)
                                {
                                    Match match = regex.Match(s.Comments.ToString());
                                    if (!match.Success || true /*ignoreFilter*/)
                                    {
                                        dtp.Rows.Add(false, p_qa[1], s.ScanID.ToString(), s.Origin.ToString(), s.IsIncremental, datetime, s.Comments.ToString(), s.IsLocked);
                                    }
                                }
                            }
                        }
                    }

                    if (dt.Rows.Count >= 1 && dtp.Rows.Count >= 1)
                    {
                        compare.Visible = true;
                        divScansForm.Visible = true;
                        ClearErrorMessage();

                        prd_latest.DataSource = dtp;
                        prd_latest.DataBind();

                        project_scans.DataSource = dt;
                        project_scans.DataBind();
                    }
                    else
                    {
                        compare.Visible = false;
                        divScansForm.Visible = false;
                        String messageStr = String.Empty;
                        String errorStr = String.Empty;
                        if (dt.Rows.Count == 0)
                            messageStr = "There are no development scans to compare for the selected project.";
                        else if (dtp.Rows.Count == 0 && config.baselineScanAge == 0)
                            messageStr = "There are no production or QA scans to compare for the selected project.";
                        else if (dtp.Rows.Count == 0)
                            messageStr = "No baseline scans were run in the selected project in the last " + config.baselineScanAge + " days.";
                        else
                            errorStr = "Scans for the baseline and development project could not be found. Please contact the administrator.";


                        if (!String.IsNullOrEmpty(messageStr))
                        {
                            log.Info(messageStr + " [" + projectName + "]");
                            ShowMessage(messageStr + "<br/>[" + projectName + "]");
                        }
                        else if (!String.IsNullOrEmpty(errorStr))
                        {
                            log.Info(errorStr);
                            ShowErrorMessage(errorStr);
                        }
                    }
                }
                catch (Exception ex)
                {
                    ShowErrorMessage("Could not fetch scan data from server.<br/>" + ex.Message);
                    log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                }
            }
            else
            {
                //no scans or no baseline project to compare to
                pdf.Visible = false;
                divScansForm.Visible = false;
                compare.Visible = false;
                project_scans.DataSource = null;
                project_scans.DataBind();

                ShowErrorMessage("No corresponding PRD baseline scan was found for the [" + projectName + "] project.<br/>Note: Incremental and No-code-changed Scans do not qualify.");
            }
        }

        private void ClearScansGridView()
        {
            prd_latest.DataSource = null;
            prd_latest.DataBind();

            project_list.DataSource = null;
            project_list.DataBind();
        }

        private String getEngineFinishTime(long scanID)
        {
            // if (config.debug) log.Debug("-------->>> getEngineFinishTime");
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScanSummary scan = SOAPservice.GetScanSummary(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), scanID, true);
                DateTime dt = new DateTime(scan.EngineFinish.Year, scan.EngineFinish.Month, scan.EngineFinish.Day, scan.EngineFinish.Hour, scan.EngineFinish.Minute, scan.EngineFinish.Second);
                if (dt.Year == 1)
                    return "N/A";
                else
                    return formatDate(dt);
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                return "N/A";
            }
        }
        private string[] getBaselineScan(string projectname, string ext)
        {
            // if (config.debug) log.Debug("-------->>> getBaselineScan");
            try
            {
                string baseline_project = projectname.Substring(0, projectname.LastIndexOf("_")) + ext;
                return Get_LastScan(baseline_project);
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }
        }
        #endregion

        #region Other Core
        private void CompareScansForProject(string projectname)
        {
            // if (config.debug) log.Debug("-------->>> CompareScansForProject");
            string[] baseline = null, latestdev = null;

            if (projectname != null)
            {
                try
                {
                    CxWSResponseLoginData login = getSessionID(CredentialUtil.GetCredential("cxgate").Username, CredentialUtil.GetCredential("cxgate").Password);
                    ViewState[CxGateViewStateKeys.SOAP_TOKEN] = login.SessionId;
                }
                catch { Response.Write("Problem getting cxgate credential"); }

                try { baseline = getBaselineScan(projectname, baseline_suffix_p); } catch { baseline = null; }
                try { latestdev = Get_LastScan(projectname); } catch { latestdev = null; }

                if (projectname.Contains("_") && baseline != null && latestdev != null)
                {
                    // Response.Write("baseline:  " + baseline[0] + "<br/>");
                    // Response.Write("latest:  " + latestdev[0] + "<br/>");
                    getComparison(new string[] { baseline[0].ToString(), latestdev[0].ToString() });
                    createPDFAndLink();
                }
                else
                {
                    String errMsg = "No PRD/dev scans found for requested project.";
                    log.Error("errMsg");
                    ShowErrorMessage(errMsg);
                }
            }
        }
        public string GetMACAddress()
        {
            // if (config.debug) log.Debug("-------->>> GetMACAddress");
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            String sMacAddress = string.Empty;
            foreach (NetworkInterface adapter in nics)
            {
                if (sMacAddress == String.Empty)// only return MAC Address from first card
                {
                    IPInterfaceProperties properties = adapter.GetIPProperties();
                    sMacAddress = adapter.GetPhysicalAddress().ToString();
                }
            }
            return sMacAddress;
        }
        private string getProperty(string property)
        {
            // if (config.debug) log.Debug("-------->>> getProperty");
            try
            {
                string[] lines = System.IO.File.ReadAllLines(HttpContext.Current.Server.MapPath("~/") + @"\cxqa.properties");

                foreach (string line in lines)
                {
                    if (line.StartsWith(property))
                    {
                        //return line.Split('|')[1];
                        return line.Substring(line.IndexOf('|') + 1);
                    }
                }
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "";
        }
        public void SortListControl(ListControl control, bool isAscending)
        {
            // if (config.debug) log.Debug("-------->>> SortListControl");

            List<ListItem> collection;

            if (isAscending)
                collection = control.Items.Cast<ListItem>()
                    .Select(x => x)
                    .OrderBy(x => x.Text)
                    .ToList();
            else
                collection = control.Items.Cast<ListItem>()
                    .Select(x => x)
                    .OrderByDescending(x => x.Text)
                    .ToList();

            control.Items.Clear();

            foreach (ListItem item in collection)
                control.Items.Add(item);
        }
        protected void project_scans_RowDataBound(object sender, GridViewRowEventArgs e)
        {
            // if (config.debug) log.Debug("-------->>> project_scans_RowDataBound");

            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                CheckBox cb = (CheckBox)e.Row.Cells[0].Controls[0];
                cb.Enabled = true;

                e.Row.Cells[0].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[4].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[7].HorizontalAlign = HorizontalAlign.Center;
            }
        }
        protected void prod_scans_RowDataBound(object sender, GridViewRowEventArgs e)
        {
            // if (config.debug) log.Debug("-------->>> prod_scans_RowDataBound");

            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                CheckBox cb = (CheckBox)e.Row.Cells[0].Controls[0];
                cb.Enabled = true;

                e.Row.Cells[0].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[4].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[7].HorizontalAlign = HorizontalAlign.Center;
            }
        }
        protected string formatDate(DateTime d)
        {
            // if (config.debug) log.Debug("-------->>> formatDate");
            return String.Format("{0:d} {0:t}", d);
        }
        private string getVersion_OLD(long scanID)
        {
            // if (config.debug) log.Debug("-------->>> getVersion_OLD");

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScansDisplayExtendedData sdd = SOAPservice.GetScansDisplayDataForAllProjects(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString());
                foreach (ScanDisplayData s in sdd.ScanList)
                {
                    if (s.ScanID == scanID)
                        return s.CxVersion;
                }
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "Version not found";
        }
        protected async void getComparison(string[] scanIDs)
        {
            // if (config.debug) log.Debug("-------->>> getComparison");

            // Current op - scan comparison
            ViewState.Add(CxGateViewStateKeys.CURRENT_OP, CxGateOp.COMPARE_SCANS);

            bool low = includeLowsInfoInReport.Checked;
            DataTable dt = new DataTable();
            dt.Columns.Add(" ", typeof(string));
            dt.Columns.Add("Previous Scan", typeof(string));
            dt.Columns.Add("New Scan", typeof(string));

            long oldscan = Int64.Parse(scanIDs[0]);
            long newscan = Int64.Parse(scanIDs[1]);

            ViewState["ids"] = oldscan + "_" + newscan;

            log.Info(ViewState[CxGateViewStateKeys.USERNAME] + " chose scans:  " + oldscan + ", " + newscan);

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScanSummary old_scan = SOAPservice.GetScanSummary(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), oldscan, true);
                CxWSResponseScanSummary new_scan = SOAPservice.GetScanSummary(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), newscan, true);

                dt.Rows.Add("Scan Risk", old_scan.ScanRisk.ToString(), new_scan.ScanRisk.ToString());
                dt.Rows.Add("LOC", old_scan.LOC.ToString(), new_scan.LOC.ToString());
                dt.Rows.Add("Files Count", old_scan.FilesCount.ToString(), new_scan.FilesCount.ToString());
                dt.Rows.Add("Project Name", old_scan.ProjectName.ToString(), new_scan.ProjectName.ToString());
                dt.Rows.Add("Team", old_scan.TeamName.ToString(), new_scan.TeamName.ToString());
                dt.Rows.Add("Preset", old_scan.Preset.ToString(), new_scan.Preset.ToString());
                dt.Rows.Add("Source Origin", old_scan.Path.ToString().Replace(";", "; "), new_scan.Path.ToString().Replace(";", "; "));
                dt.Rows.Add("Scan Type", old_scan.ScanType.ToString(), new_scan.ScanType.ToString());

                string old_version = "", new_version = "";
                try
                {
                    String json = await getVersion(oldscan);
                    dynamic t = JObject.Parse(json);
                    old_version = t.scanState.cxVersion;
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                }

                try
                {
                    String json = await getVersion(newscan);
                    dynamic t = JObject.Parse(json);
                    new_version = t.scanState.cxVersion;
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                }

                dt.Rows.Add("Cx Version", old_version, new_version);
                dt.Rows.Add("Is Incremental", old_scan.IsIncremental.ToString(), new_scan.IsIncremental.ToString());
                dt.Rows.Add("Scan Comment", old_scan.Comment.ToString() == "" ? " " : old_scan.Comment.ToString(), new_scan.Comment.ToString() == "" ? " " : new_scan.Comment.ToString());

                DateTime e = new DateTime(old_scan.ScanQueued.Year, old_scan.ScanQueued.Month, old_scan.ScanQueued.Day, old_scan.ScanQueued.Hour, old_scan.ScanQueued.Minute, old_scan.ScanQueued.Second);
                DateTime f = new DateTime(new_scan.ScanQueued.Year, new_scan.ScanQueued.Month, new_scan.ScanQueued.Day, new_scan.ScanQueued.Hour, new_scan.ScanQueued.Minute, new_scan.ScanQueued.Second);
                dt.Rows.Add("Scan Queued", e.Year == 1 ? "N/A" : formatDate(e), f.Year == 1 ? "N/A" : formatDate(f));

                DateTime a = new DateTime(old_scan.EngineStart.Year, old_scan.EngineStart.Month, old_scan.EngineStart.Day, old_scan.EngineStart.Hour, old_scan.EngineStart.Minute, old_scan.EngineStart.Second);
                DateTime b = new DateTime(new_scan.EngineStart.Year, new_scan.EngineStart.Month, new_scan.EngineStart.Day, new_scan.EngineStart.Hour, new_scan.EngineStart.Minute, new_scan.EngineStart.Second);
                dt.Rows.Add("Scan Start", a.Year == 1 ? "N/A" : formatDate(a), b.Year == 1 ? "N/A" : formatDate(b));

                DateTime c = new DateTime(old_scan.EngineFinish.Year, old_scan.EngineFinish.Month, old_scan.EngineFinish.Day, old_scan.EngineFinish.Hour, old_scan.EngineFinish.Minute, old_scan.EngineFinish.Second);
                DateTime d = new DateTime(new_scan.EngineFinish.Year, new_scan.EngineFinish.Month, new_scan.EngineFinish.Day, new_scan.EngineFinish.Hour, new_scan.EngineFinish.Minute, new_scan.EngineFinish.Second);
                dt.Rows.Add("Scan Complete", c.Year == 1 ? "N/A" : formatDate(c), d.Year == 1 ? "N/A" : formatDate(d));

                dt.Rows.Add("Total Scan Time", a.Year == 1 ? "N/A" : (TimeSpan.FromMinutes(Int64.Parse(old_scan.TotalScanTime.ToString()) / 10000000.0 / 60.0)).ToString(),
                                                b.Year == 1 ? "N/A" : (TimeSpan.FromMinutes(Int64.Parse(new_scan.TotalScanTime.ToString()) / 10000000.0 / 60.0)).ToString());

                string old_lang = "", new_lang = "";

                foreach (CxWSQueryLanguageState s in old_scan.ScanLanguageStateCollection)
                {
                    old_lang += s.LanguageName + ", ";
                }

                foreach (CxWSQueryLanguageState s in new_scan.ScanLanguageStateCollection)
                {
                    new_lang += s.LanguageName + ", ";
                }

                dt.Rows.Add("Languages", old_lang.Trim().Trim(','), new_lang.Trim().Trim(','));
                dt.Rows.Add("Custom Field Value(s)", ViewState[CxGateViewStateKeys.CUSTOM_FIELDS].ToString() == "" ? " " : ViewState[CxGateViewStateKeys.CUSTOM_FIELDS].ToString(), ViewState[CxGateViewStateKeys.CUSTOM_FIELDS].ToString() == "" ? " " : ViewState[CxGateViewStateKeys.CUSTOM_FIELDS].ToString());

                comparison.DataSource = dt;
                comparison.DataBind();

                divScansForm.Visible = false;
                divComparisonForm.Visible = true;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            //===========GETSCANCOMPARESUMMARY===============

            DataTable scst = new DataTable();
            scst.Columns.Add(" ", typeof(string));
            scst.Columns.Add("High", typeof(long));
            scst.Columns.Add("Medium", typeof(long));
            if (low)
            {
                scst.Columns.Add("Low", typeof(long));
                scst.Columns.Add("Info", typeof(long));
            }
            scst.Columns.Add("Total", typeof(long));

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                log.Info("Old Scan:  " + oldscan);
                log.Info("New Scan:  " + newscan);

                CxWSResponseScanCompareSummary scs = SOAPservice.GetScanCompareSummary(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), oldscan, newscan);
                if (!low)
                {
                    scst.Rows.Add("New Issues", scs.High.New, scs.Medium.New, (scs.High.New + scs.Medium.New));
                    scst.Rows.Add("Resolved Issues", scs.High.Fixed, scs.Medium.Fixed, (scs.High.Fixed + scs.Medium.Fixed));
                    scst.Rows.Add("Recurrent Issues", scs.High.ReOccured, scs.Medium.ReOccured, (scs.High.ReOccured + scs.Medium.ReOccured));
                }
                else
                {
                    scst.Rows.Add("New Issues", scs.High.New, scs.Medium.New, scs.Low.New, scs.Info.New, (scs.High.New + scs.Medium.New + scs.Low.New + scs.Info.New));
                    scst.Rows.Add("Resolved Issues", scs.High.Fixed, scs.Medium.Fixed, scs.Low.Fixed, scs.Info.Fixed, (scs.High.Fixed + scs.Medium.Fixed + scs.Low.Fixed + scs.Info.Fixed));
                    scst.Rows.Add("Recurrent Issues", scs.High.ReOccured, scs.Medium.ReOccured, scs.Low.ReOccured, scs.Info.ReOccured, (scs.High.ReOccured + scs.Medium.ReOccured + scs.Low.ReOccured + scs.Info.ReOccured));
                }

                counts.DataSource = scst;
                counts.DataBind();

                divScansForm.Visible = false;
                divComparisonForm.Visible = true;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }


            //===========GETRESULTSFORSCAN-NE===============

            DataTable ne = new DataTable();
            //ne.Columns.Add("ID", typeof(string));
            ne.Columns.Add("Query", typeof(string));
            ne.Columns.Add("Not-Exploitables", typeof(string));
            //ne.Columns.Add("Source File", typeof(string));
            //ne.Columns.Add("Dest File", typeof(string));
            //ne.Columns.Add("Severity", typeof(string));
            //ne.Columns.Add("Comments", typeof(string));

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponceScanResults results = SOAPservice.GetResultsForScan(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), newscan);
                List<queryName> qsummary = new List<queryName>();
                foreach (CxWSSingleResultData r in results.Results)
                {
                    if (r.State == 1)//not exploitable
                    {
                        string sev = "Informational";
                        switch (r.Severity)
                        {
                            case 3:
                                sev = "High";
                                break;
                            case 2:
                                sev = "Medium";
                                break;
                            case 1:
                                sev = "Low";
                                break;
                        }//end switch

                        //string comment = Get_Comment_History(newscan, r.PathId);
                        //if (comment.Contains(projectName))
                        //{

                        int i = checkList(Get_Query_Name(newscan, r.QueryId) + " (" + sev + ")", qsummary);
                        if (i != -1)
                            qsummary[i].id++;
                        else
                            qsummary.Add(new queryName(Get_Query_Name(newscan, r.QueryId) + " (" + sev + ")", 1));
                        //ne.Rows.Add(r.PathId.ToString(), Get_Query_Name(newscan, r.QueryId), "Marked Not Exploitable", r.SourceFile, r.DestFile, sev, comment);
                        //}
                    }
                }

                foreach (queryName qn in qsummary)
                    ne.Rows.Add(new String[] { qn.name, qn.id.ToString() });

                if (ne.Rows.Count == 0)
                {
                    ne.Rows.Add(new String[] { "-- No Not-Exploitable results found --", "0" });
                }

                not_exploitable.DataSource = ne;
                not_exploitable.DataBind();

                divScansForm.Visible = false;
                divComparisonForm.Visible = true;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            //return true;
        }
        private bool checkList(long i)
        {
            // if (config.debug) log.Debug("-------->>> checkList(i)");

            foreach (queryName q in queryNames)
            {
                if (q.id == i)
                    return true;
            }
            return false;
        }
        private int checkList(string name, List<queryName> list)
        {
            // if (config.debug) log.Debug("-------->>> checkList(name, list)");

            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].name.Equals(name))
                    return i;
            }
            return -1;
        }
        private string getNameFromList(long i)
        {
            // if (config.debug) log.Debug("-------->>> getNameFromList");
            foreach (queryName q in queryNames)
            {
                if (q.id == i)
                    return q.name;
            }
            return "Unknown";
        }
        private string Get_Query_Name(long scanid, long queryid)
        {
            // if (config.debug) log.Debug("-------->>> Get_Query_Name");
            if (checkList(queryid))//if name already found, don't look up again; pull from list
            {
                return getNameFromList(queryid);
            }
            else
            {
                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                    SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                    CxWSResponceQuerisForScan queries = SOAPservice.GetQueriesForScan(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), scanid);

                    foreach (CxWSQueryVulnerabilityData q in queries.Queries)
                    {
                        if (q.QueryId == queryid)
                        {
                            queryNames.Add(new queryName(q.QueryName, queryid));
                            return q.QueryName;
                        }
                    }
                    queryNames.Add(new queryName("Unknown", queryid));
                    return "Unknown";
                }
                catch (Exception e)
                {
                    log.Error(e.Message + Environment.NewLine + e.StackTrace);
                    return "Unknown";
                }
            }
        }
        private string Get_Comment_History(long scanid, long pathid)
        {
            // if (config.debug) log.Debug("-------->>> Get_Comment_History");
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
                SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponceResultPath history = SOAPservice.GetPathCommentsHistory(ViewState[CxGateViewStateKeys.SOAP_TOKEN].ToString(), scanid, pathid, ResultLabelTypeEnum.Remark);

                return history.Path.Comment.Replace("ÿ", "[newline]");
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return "";
            }
        }
        private void createPDFAndLink()
        {
            // if (config.debug) log.Debug("-------->>> createPDFAndLink");

            String username = ViewState[CxGateViewStateKeys.USERNAME].ToString();
            log.Info(username + " generating report.");
            try
            {
                StringWriter sw = new StringWriter();
                HtmlTextWriter output = new HtmlTextWriter(sw);

                log.Info("Adding comparison report.");
                this.ScanComparePanel.RenderControl(output);

                var pdfConfig = new TheArtOfDev.HtmlRenderer.PdfSharp.PdfGenerateConfig();
                pdfConfig.SetMargins(25);

                pdfConfig.PageOrientation = PdfSharp.PageOrientation.Landscape;
                if (config.pageSize.ToLower().Equals("letter"))
                    pdfConfig.PageSize = PdfSharp.PageSize.Letter;
                else if (config.pageSize.ToLower().Equals("legal"))
                    pdfConfig.PageSize = PdfSharp.PageSize.Legal;
                else if (config.pageSize.ToLower().Equals("tabloid"))
                    pdfConfig.PageSize = PdfSharp.PageSize.Tabloid;
                else
                    pdfConfig.PageSize = PdfSharp.PageSize.Letter;

                log.Info("Generating PDF.");

                DateTime reportGenerationTime = DateTime.Now;
                String cssPath = HttpContext.Current.Server.MapPath("~/") + @"resources/stylesheets/cxgate_print.css";
                String logoPath = HttpContext.Current.Server.MapPath("~/") + @"resources/images/logo.png";
                StringBuilder html = new StringBuilder();
                // html.Append("<html><head><link href=\"" + cssPath + "\"></head><body>");
                html.Append("<html><head></head><body>");
                String header = "<img src=\"" + logoPath + "\" width=150 height=20 /><br/><b>CxGate v" + VERSION + "</b><p/>";
                html.Append(header);
                html.Append(sw.ToString().Replace("<th scope=\"col\">", "<td>").Replace("</th>", "</td>"));

                // html.Append("<table border=1><tr><td>First</td><td style=\"width: 200px; word-wrap: overflow;\">secondddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd</td><td>third</td></tr></table>");
                html.Append("</body></html>");

                // Read CSS to apply to the PDF
                String styleSheetStr = File.ReadAllText(HttpContext.Current.Server.MapPath("~/") + @"/resources/stylesheets/cxgate_print.css");
                CssData cssData = PdfGenerator.ParseStyleSheet(styleSheetStr, true);

                // Generate the PDF
                // PdfDocument document = PdfGenerator.GeneratePdf(html, config.PageSize, 20, cssData);
                PdfDocument document = PdfGenerator.GeneratePdf(html.ToString(), pdfConfig.PageSize, 30, cssData);

                foreach (PdfSharp.Pdf.PdfPage page in document.Pages)
                {
                    XGraphics gfx = XGraphics.FromPdfPage(page);
                    XFont font = new XFont("Verdana", 11, XFontStyle.Regular);
                    gfx.DrawString("  CxGate Report | " + DateTime.Now + " | Run by:  " + ViewState[CxGateViewStateKeys.USER_EMAIL].ToString(), font, XBrushes.Black, new XRect(0, 0, page.Width, 20), XStringFormats.BottomCenter);
                }

                String filename = ViewState["ids"].ToString() + ".pdf";
                String fullpath = Server.MapPath("~") + "/CxGateReports/" + filename;
                document.Save(fullpath);

                //pdflink.Text = config.cxserver + "/CxGate/CxGateReports/" + filename;
                StringBuilder sb = new StringBuilder();
                sb.Append("prompt('The report has been saved.  Copy the report link below to your change request.','" + config.cxserver + "/CxGate/CxGateReports/" + filename + "')");
                ClientScript.RegisterStartupScript(GetType(), "Javascript", sb.ToString(), true);

                log.Info("PDF saved/served:  " + filename);
            }
            catch (Exception e)
            {
                log.Error(e.GetType());
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }
        public override void VerifyRenderingInServerForm(Control control)
        {
            /* Confirms that an HtmlForm control is rendered for the specified ASP.NET
               server control at run time. */
        }
        protected void counts_RowDataBound(object sender, GridViewRowEventArgs e)
        {
            // if (config.debug) log.Debug("-------->>> counts_RowDataBound");

            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                e.Row.Cells[1].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[2].HorizontalAlign = HorizontalAlign.Center;
                //e.Row.Cells[3].HorizontalAlign = HorizontalAlign.Center;
                //e.Row.Cells[4].HorizontalAlign = HorizontalAlign.Center;
                e.Row.Cells[3].HorizontalAlign = HorizontalAlign.Center;
            }
        }
        protected void not_exploitable_RowDataBound(object sender, GridViewRowEventArgs e)
        {
            // if (config.debug) log.Debug("-------->>> not_exploitable_RowDataBound");

            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                e.Row.Cells[1].HorizontalAlign = HorizontalAlign.Center;
            }
        }
        protected async Task GenerateAndEmailDetailsReport()
        {
            // if (config.debug) log.Debug("-------->>> GenerateAndEmailDetailsReport");

            try
            {
                Process process = new Process();

                TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
                int secondsSinceEpoch = (int)t.TotalSeconds;

                process.StartInfo.FileName = HttpContext.Current.Server.MapPath("~/") + "\\bin\\extract.exe";
                log.Debug("Extract process run: " + process.StartInfo.FileName);
                String args = projectsTeamsList.SelectedValue + " " + ViewState[CxGateViewStateKeys.USER_EMAIL].ToString() +
                    " \"" + HttpContext.Current.Server.MapPath("~/") + "reports\\CxExtract_" + secondsSinceEpoch + ".xlsx\" " + config.cxserver + " \"" +
                    HttpContext.Current.Server.MapPath("~/") + @"cxqa.properties" + "\"";

                if (config.debug)
                    log.Info(args);

                process.StartInfo.Arguments = jwtToken + " " + args;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = false;
                process.StartInfo.RedirectStandardError = false;
                process.StartInfo.CreateNoWindow = false;
                process.Start();

                ShowMessage("Report has been requested and will be sent to " + ViewState[CxGateViewStateKeys.USER_EMAIL].ToString() + ".");
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                ShowErrorMessage("Failed to request the report.  Please contact your administrator.");
            }
        }
        private async Task<string> getVersion(long scanID)
        {
            // if (config.debug) log.Debug("-------->>> getVersion");

            try
            {
                HttpClient client = new HttpClient();
                String url = config.cxserver + "/cxrestapi/sast/scans/" + scanID;
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync(url);
                var responseString = await response.Content.ReadAsStringAsync();

                return responseString;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "Error";
        }
        #endregion

        #region User Info
        private async Task<string> getLoggedInProfile()
        {
            // if (config.debug) log.Debug("-------->>> getLoggedInProfile");

            try
            {
                HttpClient client = new HttpClient();
                String url = config.cxserver + "/cxrestapi/auth/myprofile";
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync(url);
                var responseString = await response.Content.ReadAsStringAsync();
                return responseString;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "Error";
        }
        #endregion

        #region Authentication - SOAP
        private CxWSResponseLoginData getSessionID(String un, String pw)
        {
            // if (config.debug) log.Debug("-------->>> getViewStateID");

            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            CxWSResponseLoginData login = null;
            CxPortalWebService SOAPservice = new CxPortalWebService(jwtToken);
            SOAPservice.Url = config.cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
            Credentials c = new Credentials();

            if (authDomainsDropDown.Text.Equals("Application"))
                c.User = un;
            else
                c.User = authDomainsDropDown.Text + "\\" + un;

            ViewState[CxGateViewStateKeys.USERNAME] = c.User;
            c.Pass = pw;
            try
            {
                login = SOAPservice.LoginV2(c, 0, false);
                if (login.IsSuccesfull)
                    return login;
                else
                    return null;
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }
        }
        protected async void login_Click_SOAP(object sender, EventArgs e)
        {
            // if (config.debug) log.Debug("-------->>> login_Click_SOAP");

            CxWSResponseLoginData login = getSessionID(user.Text, pass.Text);
            if (login != null)
            {
                if (login.IsSuccesfull)
                {
                    ClearErrorMessage();
                    ViewState[CxGateViewStateKeys.SOAP_TOKEN] = login.SessionId;

                    String un = "";
                    if (authDomainsDropDown.Text.Equals("Application"))
                        un = user.Text;
                    else
                        un = authDomainsDropDown.Text + "\\" + user.Text;

                    String token = await getAuthToken(un, pass.Text);
                    ViewState[CxGateViewStateKeys.TOKEN] = token;

                    ViewState.Add(CxGateViewStateKeys.USER_EMAIL, login.Email);
                    if (config.debug) log.Debug("Email address of requester:  " + login.Email);

                    ShowProjectsForm(config.showDetailsReport);

                    log.Info(user.Text + " logged in.");
                }
                else
                {
                    log.Info(user.Text + " could not log in:  " + login.ErrorMessage);
                    ShowErrorMessage("Could not log in as " + user.Text + ".  Please try again.");
                }
            }
            else
            {
                ShowErrorMessage("Could not log in as " + ViewState[CxGateViewStateKeys.USERNAME] + ".  Please try again.");
            }
        }
        #endregion

        #region Authentication - REST
        private async Task<string> getJWT(String refreshToken)
        {
            var body = new Dictionary<string, string>
                {
                    { "refresh_token", refreshToken },
                    { "grant_type", "refresh_token" },
                    { "scope", "sast_api" },
                    { "client_id", "resource_owner_sast_client" },
                    { "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" }
                };

            String jwt = String.Empty;
            try
            {
                String response = await authPOST(body);
                dynamic json = JObject.Parse(response);
                // Refresh the refresh token in the view state
                ViewState[CxGateViewStateKeys.TOKEN] = (String)json.refresh_token;
                jwt = json.access_token;
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Request for authentication token failed.<br/>" + ex.Message);
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            if (String.IsNullOrEmpty(jwt))
            {
                log.Error("Unauthenticated access. Redirecting to login page.");
                ViewState[CxGateViewStateKeys.USERNAME] = null;
                ViewState[CxGateViewStateKeys.TOKEN] = null;
                Response.Redirect("index.aspx", false);
                return null;
            }

            return jwt;
        }

        private async Task<string> getAuthToken(String un, String pw)
        {
            var body = new Dictionary<string, string>
                {
                    { "username", un },
                    { "password", pw },
                    { "grant_type", "password" },
                    { "scope", "offline_access sast_api" },
                    { "client_id", "resource_owner_sast_client" },
                    { "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" }
                };
            String token = String.Empty;
            try
            {
                String response = await authPOST(body);
                dynamic json = JObject.Parse(response);
                token = json.refresh_token;
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Could not authenticate user [" + un + "].<br/>" + ex.Message);
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
            return token;
        }

        private async Task<string> authPOST(Dictionary<string, string> body)
        {
            // if (config.debug) log.Debug("-------->>> getToken");

            HttpClient client = new HttpClient();
            String url = config.cxserver + "/cxrestapi/auth/identity/connect/token";

            var content = new FormUrlEncodedContent(body);
            var response = await client.PostAsync(url, content);

            return await response.Content.ReadAsStringAsync();
        }
        #endregion

    }

    public class UserPass
    {
        public string Username, Password;
        public UserPass(string u, string p)
        {
            this.Username = u;
            this.Password = p;
        }
    }

    public static class CredentialUtil
    {
        public static UserPass GetCredential(string target)
        {
            var cm = new Credential { Target = target };
            if (!cm.Load())
            {
                return null;
            }

            //UserPass is just a class with two string properties for user and pass
            return new UserPass(cm.Username, cm.Password);
        }

        public static bool SetCredentials(
             string target, string username, string password, PersistanceType persistenceType)
        {
            return new Credential
            {
                Target = target,
                Username = username,
                Password = password,
                PersistanceType = persistenceType
            }.Save();
        }

        public static bool RemoveCredentials(string target)
        {
            return new Credential { Target = target }.Delete();
        }
    }

    public class queryName
    {
        public long id;
        public string name;

        public queryName()
        {

        }

        public queryName(string s, long l)
        {
            this.id = l;
            this.name = s;
        }
    }
}
