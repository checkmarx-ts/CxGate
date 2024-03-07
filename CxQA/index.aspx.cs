using CredentialManagement;
using CxQA.CX;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
using System.Runtime.Remoting.Contexts;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using TheArtOfDev.HtmlRenderer.Core;
using TheArtOfDev.HtmlRenderer.PdfSharp;
using static OfficeOpenXml.ExcelErrorValue;
using ListItem = System.Web.UI.WebControls.ListItem;

namespace CxQA
{
    /// <summary>
    /// Enumeration of operations that this 
    /// application can perform. This is used
    /// to track what UI elements to render.
    /// </summary>
    public enum CxGateOp
    {
        LIST_PROJECTS,
        LIST_SCANS,
        COMPARE_SCANS,
        GENERATE_REPORT
    }
    /// <summary>
    /// Keys used in the ViewState.
    /// </summary>
    public struct ViewStateKeys
    {
        public static readonly string TOKEN = "cx_token";
        public static readonly string SOAP_TOKEN = "cx_soap_token";

        public static readonly string USERNAME = "cx_user";
        public static readonly string FIRST_NAME = "cx_first_name";
        public static readonly string LAST_NAME = "cx_last_name";
        public static readonly string USER_EMAIL = "cx_user_email";

        public static readonly string PROJECT_CUSTOM_FIELDS_MAP = "cx_custom_fields_map";
        public static readonly string CUSTOM_FIELDS = "cx_custom_fields";
        public static readonly string CURRENT_OP = "cx_current_op";
    }

    /// <summary>
    /// Keys for data entries stored in the session
    /// </summary>
    public struct SessionDataKeys
    {
        public static readonly string PROJECTS = "cx_data_projects";
        public static readonly string TEAMS = "cx_data_teams";
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

    [Serializable]
    public class CxCustomField
    {
        public int Id { get; set; }
        public String Value { get; set; }
        public String Name { get; set; }
    }

    public partial class Index : System.Web.UI.Page
    {
        #region Variable declarations
        private static readonly String VERSION = "3.03";
        private CxGateConfig config = new CxGateConfig();
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly String baseline_suffix_p = "_PRD";
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

            if (ViewState[ViewStateKeys.TOKEN] == null)
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
            bool isAuth = ViewState != null && ViewState[ViewStateKeys.TOKEN] != null;
            // if (config.debug) log.Debug("-------->>> IsAuthenticated : " + isAuth);
            return isAuth;
        }
        #endregion

        private void ShowDivs()
        {
            // if (config.debug) log.Debug("-------->>> ShowDivs");

            CxGateOp op = (CxGateOp)ViewState[ViewStateKeys.CURRENT_OP];
            if (config.debug) log.Debug("Current operation in ViewState is [" + op + "]");

            switch (op)
            {
                default:
                case CxGateOp.LIST_PROJECTS:
                    GetProjects();
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
                string projectName = Request.QueryString["project"];
                int projectId = GetProjectIdFromCache(projectName);
                if (!String.IsNullOrEmpty(projectName)) CompareScansForProject(projectId, projectName);
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
                        String refreshToken = ViewState[ViewStateKeys.TOKEN].ToString();
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
                            CompareScans(); break;
                        case "listScans":
                        case "project_list":
                            ListScans(); break;
                        case "pdf":
                            GenerateComparisonReport(); break;
                        case "projectsTeamsList":
                            GenerateAndEmailDetailsReport(); break;
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
                ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.LIST_PROJECTS);

                String refreshToken = await getAuthToken(username, pass.Text);

                ViewState.Add(ViewStateKeys.USERNAME, username);
                ViewState.Add(ViewStateKeys.TOKEN, refreshToken);
                // TODO: REMOVE
                ViewState.Add(ViewStateKeys.SOAP_TOKEN, String.Empty);

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

                    ViewState.Add(ViewStateKeys.USER_EMAIL, email);
                    ViewState.Add(ViewStateKeys.FIRST_NAME, firstName);
                    ViewState.Add(ViewStateKeys.LAST_NAME, lastName);

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

            String user = ViewState[ViewStateKeys.USERNAME].ToString();
            String token = ViewState[ViewStateKeys.TOKEN].ToString();

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

                ViewState[ViewStateKeys.USERNAME] = null;
                ViewState[ViewStateKeys.TOKEN] = null;
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
        protected void CompareScans()
        {
            // if (config.debug) log.Debug("-------->>> CompareScans");

            ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.COMPARE_SCANS);

            int checked_count = 0;
            bool noscanrun = false;
            string[] scanIDs = new string[2];
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

            string errMsg = string.Empty;
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

            if (!string.IsNullOrEmpty(errMsg))
            {
                getScans();
                ShowMessage(errMsg);
            }
        }

        protected void GenerateComparisonReport()
        {
            // if (config.debug) log.Debug("-------->>> GenerateComparisonReport");

            // Current op
            ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.GENERATE_REPORT);

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
        protected void ListScans()
        {
            // if (config.debug) log.Debug("-------->>> ListScans");

            // Current op
            ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.LIST_SCANS);

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
        private void GetProjects()
        {
            // if (config.debug) log.Debug("-------->>> GetProjects");

            if (project_list.Items.Count > 0) return;

            try
            {
                String endpoint = "/cxrestapi/projects";

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("2.2", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    dynamic projects = JsonConvert.DeserializeObject(responseString);
                    log.Debug(">>>>>> Adding project to session");
                    // Save projects in session
                    Session.Add(SessionDataKeys.PROJECTS, projects);
                    log.Debug("Looping over projects to add to project list");
                    foreach (var p in projects)
                    {
                        if (p.name.ToString().ToLower().Contains("_dev"))
                        {
                            string projectIdStr = p.id.ToString();
                            int projectId = int.Parse(projectIdStr);

                            project_list.Items.Add(new ListItem(p.name.ToString(), projectIdStr));

                            // If the project contains custom field values,
                            // save them in the session in the CUSTOM_FIELDS key.
                            if (p.customFields.Count > 0)
                            {
                                List<CxCustomField> cxCustomFieldList = new List<CxCustomField>();
                                foreach (var customField in p.customFields)
                                {
                                    CxCustomField cxCustomField = new CxCustomField() { Id = int.Parse(customField.id.ToString()), Name = customField.name.ToString(), Value = customField.value.ToString() };
                                    log.Debug("Found custom field(s) in project [" + p.name + "]. Custom Field : [" + cxCustomField.Name + "=" + cxCustomField.Value + "]");
                                    cxCustomFieldList.Add(cxCustomField);
                                }

                                Dictionary<int, List<CxCustomField>> customFields = new Dictionary<int, List<CxCustomField>>();

                                if (!customFields.ContainsKey(projectId) && cxCustomFieldList.Count > 0)
                                {
                                    customFields.Add(projectId, cxCustomFieldList);
                                }
                                log.Debug("Adding Custom Field Map to view state.");
                                ViewState[ViewStateKeys.PROJECT_CUSTOM_FIELDS_MAP] = customFields;
                            }
                        }
                    }

                    // Sort first, and then add the 'Select a project or...' entry at the top
                    SortListControl(project_list, true);
                    project_list.Items.Insert(0, new ListItem("Select a project...", "-1"));
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch project data from server.<br/>Please see log for details.");
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

            log.Debug("<<<<<<< Fetching projects FROM session");
            dynamic projects = Session[SessionDataKeys.PROJECTS];

            try
            {
                String endpoint = "/cxrestapi/auth/teams";

                log.Debug("Calling GET on endpoint " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("2.2", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;

                if (httpResponse.IsSuccessStatusCode)
                {
                    Dictionary<String, String> teamsMap = new Dictionary<String, String>();

                    log.Debug("Deserializing TEAM response string");
                    dynamic teams = JsonConvert.DeserializeObject(responseString);

                    // Add teams to list
                    log.Debug("Looping over teams to add to projectsteams list");
                    if (teams != null)
                    {
                        foreach (var t in teams)
                        {
                            teamsMap.Add(t.id.ToString(), t.fullName.ToString());
                            projectsTeamsList.Items.Add(new ListItem(t.fullName.ToString(), t.fullName.ToString()));
                        }

                        Session.Add(SessionDataKeys.TEAMS, teamsMap);
                    }

                    // Add team + project path to list
                    log.Debug("Looping over projects to add to projectsteams list");
                    if (projects != null)
                    {
                        foreach (var p in projects)
                        {
                            // Construct team+project path
                            String teamName = String.Empty;
                            if (teamsMap.TryGetValue(p.teamId.ToString(), out teamName))
                            {
                                var fullProjectPath = teamName + "/" + p.name.ToString();
                                projectsTeamsList.Items.Add(new ListItem(fullProjectPath, p.id.ToString()));
                            }
                        }
                    }

                    // Sort first, and then add the 'Select a project or...' entry at the top
                    SortListControl(projectsTeamsList, true);
                    projectsTeamsList.Items.Insert(0, new ListItem("Select a project or team...", "-1"));
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch project/team data from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch project/team data from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }
        private void Get_Project_Properties(int pid)
        {
            // if (config.debug) log.Debug("-------->>> Get_Project_Properties");

            log.Debug("<<<<<<< Fetching custom fields");
            dynamic customFieldsMap = ViewState[ViewStateKeys.PROJECT_CUSTOM_FIELDS_MAP];

            log.Debug("Looking for custom fields from project id " + pid);
            StringBuilder values = new StringBuilder();

            if (customFieldsMap != null && customFieldsMap.ContainsKey(pid))
            {                
                List<CxCustomField> fields = customFieldsMap[pid];
                foreach (CxCustomField field in fields)
                {
                    values.Append(field.Value);
                    values.Append(" ");
                }
            }
            log.Debug("Adding custom fields [" + values.ToString() + "] to viewstate.");
            ViewState[ViewStateKeys.CUSTOM_FIELDS] = values.ToString();
        }
        #endregion

        #region Scan Data

        private string[] GetLastScan(int projectId, String projectName)
        {
            // if (config.debug) log.Debug("-------->>> GetLastScan");

            try
            {
                String endpoint = "/cxrestapi/sast/scans?last=1&scanStatus=Finished&projectId=" + projectId;

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("1.0", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    dynamic scan = JsonConvert.DeserializeObject(responseString);
                    
                    return new string[] { scan[0].id.ToString(), projectName, projectId.ToString() };
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch last scan from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch last scan from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return null;
        }

        private dynamic GetScan(int scanId)
        {
            // if (config.debug) log.Debug("-------->>> GetScan");

            try
            {
                String endpoint = "/cxrestapi/sast/scans/" + scanId;

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("1.1", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    return JsonConvert.DeserializeObject(responseString);
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch requested scan from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch requested scan from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return null;
        }

        private dynamic GetScanList(int projectId)
        {
            // if (config.debug) log.Debug("-------->>> GetScanList");

            try
            {
                String endpoint = "/cxrestapi/sast/scans?scanStatus=Finished&projectId=" + projectId;

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("1.0", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    return JsonConvert.DeserializeObject(responseString); 
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch scan list from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch scan list from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return null;
        }

        private int GetProjectIdFromCache (String projectName)
        {
            // if (config.debug) log.Debug("-------->>> GetProjectIdFromCache");

            int projectId = -1;
            log.Debug("<<<<<<< Fetching projects FROM session");
            dynamic projects = Session[SessionDataKeys.PROJECTS];
            if (projects != null)
            {
                log.Debug("Looping over projects to lookup projectId");
                foreach (var p in projects)
                {
                    if (string.Equals(p.name.ToString(), projectName, StringComparison.OrdinalIgnoreCase))
                    {
                        projectId = p.id;
                        log.Debug("Found project id [" + projectId + "] for project [" + projectName + "]");
                    }
                }
            }
            return projectId;
        }

        private void getScans()
        {
            // if (config.debug) log.Debug("-------->>> getScans");

            ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.LIST_SCANS);
            if (project_list.SelectedItem.Value.Equals("-1")) return;

            ClearScansGridView();

            String projectName = project_list.SelectedItem.Text;
            int projectId = int.Parse(project_list.SelectedItem.Value);
            // int projectId = GetProjectIdFromCache (projectName);

            log.Info(projectName + " selected by " + ViewState[ViewStateKeys.USERNAME]);
            divComparisonForm.Visible = false;

            string[] p_prd = null;
            try {

                p_prd = getBaselineScan(projectName, baseline_suffix_p); 
            }
            catch { p_prd = null; }

            if (project_list.SelectedIndex != 0 && (p_prd != null))
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
                    Regex regex = new Regex(config.commentsFilterRegEx);
                    log.Info("Comment filtering pattern applied to scans: [" + config.commentsFilterRegEx + "]");

                    Get_Project_Properties(int.Parse(project_list.SelectedItem.Value));
                    dynamic sdd = GetScanList(projectId);
                    if (sdd != null)
                    {
                        foreach (var s in sdd)
                        {
                            var finishedOn = DateTime.Parse(s.dateAndTime.finishedOn.ToString());
                            var isIncremental = bool.Parse(s.isIncremental.ToString());
                            var scanId = int.Parse(s.id.ToString());
                            var comment = s.comment.ToString();
                            var isLocked = bool.Parse(s.isLocked.ToString());
                            var origin = s.origin.ToString();

                            string datetime = finishedOn.Month.ToString("D2") + "/" + finishedOn.Day.ToString("D2") + "/" + finishedOn.Year +
                                " " + finishedOn.Hour.ToString("D2") + ":" + finishedOn.Minute.ToString("D2") + ":" + finishedOn.Second.ToString("D2");
                            if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * config.devScanAge)) > 0 || config.devScanAge == 0)
                            {
                                Match match = regex.Match(comment);
                                if ((!match.Success || ignoreFilter) && !isIncremental)
                                {
                                    dt.Rows.Add(false, projectName, scanId, origin, isIncremental, getEngineFinishTime(finishedOn), comment, isLocked);
                                }
                            }
                        }
                    }

                    if (p_prd != null)
                    {
                        sdd = GetScanList(int.Parse(p_prd[2]));
                        if (sdd != null)
                        {
                            foreach (var s in sdd)
                            {
                                var finishedOn = DateTime.Parse(s.dateAndTime.finishedOn.ToString());
                                var isIncremental = bool.Parse(s.isIncremental.ToString());
                                var scanId = int.Parse(s.id.ToString());
                                var comment = s.comment.ToString();
                                var isLocked = bool.Parse(s.isLocked.ToString());
                                var origin = s.origin.ToString();

                                string datetime = finishedOn.Month.ToString("D2") + "/" + finishedOn.Day.ToString("D2") + "/" + finishedOn.Year +
                                    " " + finishedOn.Hour.ToString("D2") + ":" + finishedOn.Minute.ToString("D2") + ":" + finishedOn.Second.ToString("D2");
                                if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * config.baselineScanAge)) > 0 || config.baselineScanAge == 0)
                                {
                                    Match match = regex.Match(comment);
                                    if (!match.Success || true /*ignoreFilter*/)
                                    {
                                        dtp.Rows.Add(false, p_prd[1], scanId, origin, isIncremental, datetime, comment, isLocked);
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
                            messageStr = "There are no production scans to compare for the selected project.";
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

        private String getEngineFinishTime(DateTime scanFinishTime)
        {
            // if (config.debug) log.Debug("-------->>> getEngineFinishTime");
            try
            {
                if (scanFinishTime.Year == 1)
                    return "N/A";
                else
                    return formatDate(scanFinishTime);
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
                int project_id = -1;

                // Get project ID
                try
                {
                    String endpoint = "/cxrestapi/projects?projectName=" + baseline_project;

                    log.Debug("Calling GET on " + endpoint);
                    HttpResponseMessage httpResponse = REST_GET("1.0", endpoint, jwtToken, null);
                    log.Debug("Reading response from GET " + endpoint);
                    String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                    if (httpResponse.IsSuccessStatusCode)
                    {
                        log.Debug("Deserializing response string");
                        dynamic project = JsonConvert.DeserializeObject(responseString);

                        project_id = project[0].id;
                    }
                    else
                    {
                        log.Error("GET call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                        ShowErrorMessage("Could not fetch project ID for PRD project from server.<br/>Please see log for details.");
                    }
                }
                catch (Exception e)
                {
                    ShowErrorMessage("Could not fetch project ID for PRD project from server.<br/>" + e.Message);
                    log.Error(e.Message + Environment.NewLine + e.StackTrace);
                }

                return GetLastScan(project_id, baseline_project);
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }
        }
        #endregion

        #region Other Core
        private void CompareScansForProject(int projectId, string projectname)
        {
            // if (config.debug) log.Debug("-------->>> CompareScansForProject");
            string[] baseline, latestdev;

            if (projectname != null)
            {
                try
                {
                    CxWSResponseLoginData login = getSessionID(CredentialUtil.GetCredential("cxgate").Username, CredentialUtil.GetCredential("cxgate").Password);
                    ViewState[ViewStateKeys.SOAP_TOKEN] = login.SessionId;
                }
                catch { Response.Write("Problem getting cxgate credential"); }

                try { baseline = getBaselineScan(projectname, baseline_suffix_p); } catch { baseline = null; }
                try { latestdev = GetLastScan(projectId, projectname); } catch { latestdev = null; }

                if (projectname.Contains("_") && baseline != null && latestdev != null)
                {
                    // Response.Write("baseline:  " + baseline[0] + "<br/>");
                    // Response.Write("latest:  " + latestdev[0] + "<br/>");
                    getComparison(new string[] { baseline[0].ToString(), latestdev[0].ToString() });
                    createPDFAndLink();
                }
                else
                {
                    String errMsg = "No PRD/DEV scans found for requested project.";
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
        
        protected async void getComparison(string[] scanIDs)
        {
            // if (config.debug) log.Debug("-------->>> getComparison");

            // Current op - scan comparison
            ViewState.Add(ViewStateKeys.CURRENT_OP, CxGateOp.COMPARE_SCANS);

            bool low = includeLowsInfoInReport.Checked;
            DataTable dt = new DataTable();
            dt.Columns.Add(" ", typeof(string));
            dt.Columns.Add("Previous Scan", typeof(string));
            dt.Columns.Add("New Scan", typeof(string));

            int oldscan = int.Parse(scanIDs[0]);
            int newscan = int.Parse(scanIDs[1]);

            ViewState["ids"] = oldscan + "_" + newscan;

            log.Info(ViewState[ViewStateKeys.USERNAME] + " chose scans:  " + oldscan + ", " + newscan);

            try
            {
                dynamic old_scan = GetScan(oldscan);
                dynamic new_scan = GetScan(newscan);

                String old_risk = old_scan.scanRisk.ToString();
                String old_LOC = old_scan.scanState.linesOfCode.ToString();
                String old_filesCount = old_scan.scanState.filesCount.ToString();
                String old_project = old_scan.project.name.ToString();
                String old_sourceOrigin = old_scan.scanState.path.ToString().Replace(";", "; ");
                String old_isIncremental = old_scan.isIncremental.ToString();
                String old_comment = old_scan.comment.ToString() == "" ? " " : old_scan.comment.ToString();
                String old_scanType = old_scan.scanType.value.ToString();

                String new_risk = new_scan.scanRisk.ToString();
                String new_LOC = new_scan.scanState.linesOfCode.ToString();
                String new_filesCount = new_scan.scanState.filesCount.ToString();
                String new_project = new_scan.project.name.ToString();
                String new_sourceOrigin = new_scan.scanState.path.ToString().Replace(";", "; ");
                String new_isIncremental = new_scan.isIncremental.ToString();
                String new_comment = new_scan.comment.ToString() == "" ? " " : new_scan.comment.ToString();
                String new_scanType = new_scan.scanType.value.ToString();

                dt.Rows.Add("Scan Risk", old_risk, new_risk);
                dt.Rows.Add("LOC", old_LOC, new_LOC);
                dt.Rows.Add("Files Count", old_filesCount, new_filesCount);
                dt.Rows.Add("Project Name", old_project, new_project);

                Dictionary<String, String> teamsMap = Session[SessionDataKeys.TEAMS] as Dictionary<String, String>;
                if (teamsMap != null)
                {
                    String oldScanTeam = String.Empty;
                    String newScanTeam = String.Empty;
                    teamsMap.TryGetValue(old_scan.owningTeamId.ToString(), out oldScanTeam);
                    teamsMap.TryGetValue(new_scan.owningTeamId.ToString(), out newScanTeam);

                    dt.Rows.Add("Team", oldScanTeam, newScanTeam);
                }
                else
                {
                    log.Error("Could not map team ID to full team name. Teams map not found in session.");
                }

                String old_preset = GetPresetName(int.Parse(old_scan.project.id.ToString()));
                String new_preset = GetPresetName(int.Parse(new_scan.project.id.ToString()));
                dt.Rows.Add("Preset", old_preset, new_preset);

                dt.Rows.Add("Source Origin", old_sourceOrigin, new_sourceOrigin);
                dt.Rows.Add("Scan Type", old_scanType, new_scanType);

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
                dt.Rows.Add("Is Incremental", old_isIncremental, new_isIncremental);
                dt.Rows.Add("Scan Comment", old_comment, new_comment);

                // Scan queue data is not available in REST API response
                // DateTime e = DateTime.Parse(old_scan.dateAndTime.startedOn.ToString());
                // DateTime f = DateTime.Parse(new_scan.dateAndTime.startedOn.ToString());
                // dt.Rows.Add("Scan Queued", e.Year == 1 ? "N/A" : formatDate(e), f.Year == 1 ? "N/A" : formatDate(f));

                DateTime a = DateTime.Parse(old_scan.dateAndTime.startedOn.ToString());
                DateTime b = DateTime.Parse(new_scan.dateAndTime.startedOn.ToString());
                dt.Rows.Add("Scan Start", a.Year == 1 ? "N/A" : formatDate(a), b.Year == 1 ? "N/A" : formatDate(b));

                DateTime c = DateTime.Parse(old_scan.dateAndTime.finishedOn.ToString());
                DateTime d = DateTime.Parse(new_scan.dateAndTime.finishedOn.ToString());
                dt.Rows.Add("Scan Complete", c.Year == 1 ? "N/A" : formatDate(c), d.Year == 1 ? "N/A" : formatDate(d));

                TimeSpan old_duration = c.Subtract(a);
                TimeSpan new_duration = d.Subtract(b);
                dt.Rows.Add("Total Scan Time", a.Year == 1 ? "N/A" : old_duration.ToString(), b.Year == 1 ? "N/A" : new_duration.ToString());

                string old_lang = "", new_lang = "";

                foreach (dynamic s in old_scan.scanState.languageStateCollection)
                {
                    old_lang += s.languageName + ", ";
                }

                foreach (dynamic s in new_scan.scanState.languageStateCollection)
                {
                    new_lang += s.languageName + ", ";
                }

                dt.Rows.Add("Languages", old_lang.Trim().Trim(','), new_lang.Trim().Trim(','));
                dt.Rows.Add("Custom Field Value(s)", ViewState[ViewStateKeys.CUSTOM_FIELDS].ToString() == "" ? " " : ViewState[ViewStateKeys.CUSTOM_FIELDS].ToString(), ViewState[ViewStateKeys.CUSTOM_FIELDS].ToString() == "" ? " " : ViewState[ViewStateKeys.CUSTOM_FIELDS].ToString());

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

                CxWSResponseScanCompareSummary scs = SOAPservice.GetScanCompareSummary(ViewState[ViewStateKeys.SOAP_TOKEN].ToString(), oldscan, newscan);
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

                CxWSResponceScanResults results = SOAPservice.GetResultsForScan(ViewState[ViewStateKeys.SOAP_TOKEN].ToString(), newscan);
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

                        string query = Get_Query_Name(newscan, r.QueryId) + " (" + sev + ")";
                        int i = checkList(query, qsummary);
                        if (i != -1)
                            qsummary[i].id++;
                        else
                            qsummary.Add(new queryName(query, 1));
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

        private dynamic GetProjectScanSettings(int projectId)
        {
            try
            {
                String endpoint = "/cxrestapi/sast/scanSettings/" + projectId;

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("1.0", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    return JsonConvert.DeserializeObject(responseString);                    
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch requested data from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch requested data from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return null;
        }

        private dynamic GetPresetName(int projectId)
        {
            try
            {
                int presetId = GetProjectScanSettings(projectId).preset.id;

                String endpoint = "/cxrestapi/sast/presets/" + presetId;

                log.Debug("Calling GET on " + endpoint);
                HttpResponseMessage httpResponse = REST_GET("1.0", endpoint, jwtToken, null);
                log.Debug("Reading response from GET " + endpoint);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    log.Debug("Deserializing response string");
                    dynamic preset = JsonConvert.DeserializeObject(responseString);
                    return preset.name;
                }
                else
                {
                    log.Error("POST call [" + url + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                    ShowErrorMessage("Could not fetch requested scan from server.<br/>Please see log for details.");
                }
            }
            catch (Exception e)
            {
                ShowErrorMessage("Could not fetch requested scan from server.<br/>" + e.Message);
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return null;
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
                    CxWSResponceQuerisForScan queries = SOAPservice.GetQueriesForScan(ViewState[ViewStateKeys.SOAP_TOKEN].ToString(), scanid);

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
        
        private void createPDFAndLink()
        {
            // if (config.debug) log.Debug("-------->>> createPDFAndLink");

            String username = ViewState[ViewStateKeys.USERNAME].ToString();
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
                    gfx.DrawString("  CxGate Report | " + DateTime.Now + " | Run by:  " + ViewState[ViewStateKeys.USER_EMAIL].ToString(), font, XBrushes.Black, new XRect(0, 0, page.Width, 20), XStringFormats.BottomCenter);
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
        protected void GenerateAndEmailDetailsReport()
        {
            // if (config.debug) log.Debug("-------->>> GenerateAndEmailDetailsReport");

            try
            {
                Process process = new Process();

                TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
                int secondsSinceEpoch = (int)t.TotalSeconds;

                process.StartInfo.FileName = HttpContext.Current.Server.MapPath("~/") + "\\bin\\extract.exe";
                log.Debug("Extract process run: " + process.StartInfo.FileName);
                String args = projectsTeamsList.SelectedValue + " " + ViewState[ViewStateKeys.USER_EMAIL].ToString() +
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

                ShowMessage("Report has been requested and will be sent to " + ViewState[ViewStateKeys.USER_EMAIL].ToString() + ".");
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

            ViewState[ViewStateKeys.USERNAME] = c.User;
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
                    ViewState[ViewStateKeys.SOAP_TOKEN] = login.SessionId;

                    String un = "";
                    if (authDomainsDropDown.Text.Equals("Application"))
                        un = user.Text;
                    else
                        un = authDomainsDropDown.Text + "\\" + user.Text;

                    String token = await getAuthToken(un, pass.Text);
                    ViewState[ViewStateKeys.TOKEN] = token;

                    ViewState.Add(ViewStateKeys.USER_EMAIL, login.Email);
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
                ShowErrorMessage("Could not log in as " + ViewState[ViewStateKeys.USERNAME] + ".  Please try again.");
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
                ViewState[ViewStateKeys.TOKEN] = (String)json.refresh_token;
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
                ViewState[ViewStateKeys.USERNAME] = null;
                ViewState[ViewStateKeys.TOKEN] = null;
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

        private HttpResponseMessage REST_POST(String endpoint, string bearerToken, Dictionary<string, string> parameters)
        {
            // if (config.debug) log.Debug("-------->>> REST_POST");

            endpoint = endpoint.StartsWith("/") ? endpoint : ("/" + endpoint);
            String url = config.cxserver + endpoint;

            HttpClient client = new HttpClient();            
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + bearerToken);            
            
            String json = parameters == null ? String.Empty : JsonConvert.SerializeObject(parameters);
            
            if (config.debug) log.Debug("Executing POST " + url + " with " + json);

            StringContent content = new StringContent(json, Encoding.UTF8, "application/json");
            return client.PostAsync(url, content).Result;
        }
        private HttpResponseMessage REST_GET(String apiVersion, String endpoint, string bearerToken, Dictionary<string, string> parameters)
        {
            // if (config.debug) log.Debug("-------->>> getToken");

            endpoint = endpoint.StartsWith("/") ? endpoint : ("/" + endpoint);
            if (parameters != null)
            {
                endpoint += string.Join("&", parameters.Select(kvp => $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value.ToString())}"));
            }
            String url = config.cxserver + endpoint;

            if (config.debug) log.Debug("Executing GET " + url);

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + bearerToken);
            client.DefaultRequestHeaders.Add("Accept", "application/json;v=" + apiVersion);

            return client.GetAsync(url).Result;
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
