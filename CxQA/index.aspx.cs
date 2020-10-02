using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.UI.WebControls;
using CxQA.CX;
using System.Data;
using System.Web;
using System.IO;
using System.Web.UI;
using TheArtOfDev.HtmlRenderer.PdfSharp;
using PdfSharp.Pdf;
using System.Net.NetworkInformation;
using CredentialManagement;
using System.Diagnostics;
using PdfSharp.Drawing;
using System.Text.RegularExpressions;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Net.Http.Headers;

namespace CxQA
{

    public partial class index : System.Web.UI.Page
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        string VERSION = "2.14.2";
        string Cxserver = "";
        string baseline_suffix_p = "";
        string baseline_suffix_q = "";
        string domain = "";
        string printwidth = "";
        int baselineScanAge = 0;
        int devScanAge = 0;
        string pagesize = "";
        bool showDetails = false;
        string commentsFilterRegEx = "";
        bool ignoreFilter = false;
        
        List<queryName> names = new List<queryName>();

        protected void Page_Load(object sender, EventArgs e)
        {
            this.Title = "CxGate " + VERSION;
            Cxserver = getProperty("cxserver");
            baseline_suffix_p = "_PRD";
            baseline_suffix_q = "_QA";

            try { showDetails = Boolean.Parse(getProperty("showDetailsReport")); } catch { showDetails = false; }
            try { domain = getProperty("domain"); } catch { domain = ""; }
            try { printwidth = getProperty("pagewidthinpixels"); } catch { printwidth = "1000"; }
            try { pagesize = getProperty("pagesize"); } catch { pagesize = "legal"; }
            try { baselineScanAge = Int32.Parse(getProperty("baselineScanAge")); } catch { baselineScanAge = 0; }
            try { devScanAge = Int32.Parse(getProperty("devScanAge")); } catch { devScanAge = 0; }
            try {
                commentsFilterRegEx = getProperty("commentsFilterRegEx");
                if(commentsFilterRegEx.Equals(""))
                    ignoreFilter = true;
            } catch { commentsFilterRegEx = ""; ignoreFilter = true; }

            if (showDetails)
            {
                details_lbl.Visible = true;
                details_select.Visible = true;
            }
            else
            {
                details_lbl.Visible = false;
                details_select.Visible = false;
            }

            if (!IsPostBack)
            {
                log4net.Config.XmlConfigurator.Configure(new FileInfo(Server.MapPath("~/log4net.config")));

                if (!domain.Equals(""))
                {
                    codomain.Items.Add(domain.ToUpper());
                    codomain.Items.Add("Application");
                }
                else
                    codomain.Items.Add("Application");
            }

            string projectname = null;

            try
            {
                projectname = Request.QueryString["project"];
                string[] baseline = null, latestdev = null;
                
                if (projectname != null)
                {
                    try
                    {
                        CxWSResponseLoginData login = getSessionID(CredentialUtil.GetCredential("cxgate").Username, CredentialUtil.GetCredential("cxgate").Password);
                        ViewState["session"] = login.SessionId;
                    }
                    catch { Response.Write("Problem getting cxgate credential"); }
                    
                    try { baseline = getBaselineScan(projectname, baseline_suffix_p); } catch { baseline = null; }
                    try { latestdev = Get_LastScan(projectname); } catch { latestdev = null; }

                    if (projectname.Contains("_") && baseline != null && latestdev != null)
                    {
                        Response.Write("baseline:  " + baseline[0] + "<br/>");
                        Response.Write("latest:  " + latestdev[0] + "<br/>");
                        getComparison(new string[] { baseline[0].ToString(), latestdev[0].ToString() });
                        makePDF();
                    }
                    else
                    {
                        Response.Redirect("error.aspx");
                    }
                }
            }
            catch(Exception ex)
            {
                Response.Write("Something went wrong.  See CxGate log.");
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }

        private void getProjectsAndTeams()
        {
            List<string> tlist = new List<string>();
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectScannedDisplayData projects = SOAPservice.GetProjectScannedDisplayData(ViewState["session"].ToString());
                foreach (ProjectScannedDisplayData p in projects.ProjectScannedList)
                {
                    if (!tlist.Contains(p.TeamName + "\\" + p.ProjectName))
                    {
                        tlist.Add(p.TeamName + "\\" + p.ProjectName);
                        extract_param.Items.Add(new ListItem(p.TeamName + "\\" + p.ProjectName, p.ProjectID.ToString()));
                    }

                    if (!tlist.Contains(p.TeamName))
                    {
                        tlist.Add(p.TeamName);
                        extract_param.Items.Insert(tlist.Count-1, new ListItem(p.TeamName, p.TeamName.ToString()));
                    }
                }

                SortListControl(extract_param, true);
                extract_param.Items.Insert(0, new ListItem("Select a project or team...", "-1"));
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private string getProperty(string property)
        {
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
            catch(Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "";
        }

        private void Get_Projects()
        {
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectScannedDisplayData projects = SOAPservice.GetProjectScannedDisplayData(ViewState["session"].ToString());
                foreach (ProjectScannedDisplayData p in projects.ProjectScannedList)
                {
                    //if(!(p.ProjectName.ToString().ToLower().EndsWith(baseline_suffix_p.ToLower()) || p.ProjectName.ToString().ToLower().EndsWith(baseline_suffix_q.ToLower())))
                    if (p.ProjectName.ToString().ToLower().Contains("_dev"))
                        project_list.Items.Add(new ListItem(p.ProjectName.ToString(), p.ProjectID.ToString()));
                }

                SortListControl(project_list, true);
                project_list.Items.Insert(0, new ListItem("Select a project...", "-1"));
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private string [] Get_LastScan(String projectname)
        {
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectScannedDisplayData projects = SOAPservice.GetProjectScannedDisplayData(ViewState["session"].ToString());
                foreach (ProjectScannedDisplayData p in projects.ProjectScannedList)
                {
                    if (p.ProjectName.ToString().ToLower().Equals(projectname.ToLower()))
                    {
                        ViewState["baselinescanid"] = p.LastScanID.ToString();
                        return new string [] { p.LastScanID.ToString(), p.ProjectName, p.ProjectID.ToString() };
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

        private void Get_Project_Properties(long pid)
        {
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponsProjectProperties properties = SOAPservice.GetProjectProperties(ViewState["session"].ToString(), pid, ScanType.UNKNOWN);
                string values = "";
                for (int i = 0; i < properties.ProjectConfig.ProjectConfig.CustomFields.Length; i++) 
                    values += properties.ProjectConfig.ProjectConfig.CustomFields[i].Value + " ";

                ViewState["CustomFields"] = values;
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private CxWSResponseLoginData getSessionID(String un, String pw)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            CxWSResponseLoginData login = null;
            CxPortalWebService SOAPservice = new CxPortalWebService();
            SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
            Credentials c = new Credentials();

            if (codomain.Text.Equals("Application"))
                c.User = un;
            else
                c.User = codomain.Text + "\\" + un;

            ViewState["user"] = c.User;
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

        protected async void login_Click(object sender, EventArgs e)
        {
            CxWSResponseLoginData login = getSessionID(user.Text, pass.Text);
            if (login != null)
            {
                if (login.IsSuccesfull)
                {
                    loginerror.Text = "";
                    ViewState["session"] = login.SessionId;

                    String un = "";
                    if (codomain.Text.Equals("Application"))
                        un = user.Text;
                    else
                        un = codomain.Text + "\\" + user.Text;

                    String token = await authREST(un, pass.Text);
                    ViewState["RESTTOKEN"] = getRESTToken(token);

                    ViewState["sendto"] = login.Email;
                    log.Info("Email address of requester:  " + login.Email);
                    login_form.Visible = false;
                    Get_Projects();
                    getProjectsAndTeams();
                    projects_form.Visible = true;
                    log.Info(user.Text + " logged in.");
                }
                else
                {
                    log.Info(user.Text + " could not log in:  " + login.ErrorMessage);
                    loginerror.Text = "Could not log in as " + user.Text + ".  Please try again.";
                }
            }
            else
            {
                loginerror.Text = "Could not log in as " + ViewState["user"] + ".  Please try again.";
            }
        }

        public string GetMACAddress()
        {
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

        private void getScans()
        {
            log.Info(project_list.SelectedItem.Text + " selected by " + ViewState["user"]);
            comparison_form.Visible = false;

            string[] p_prd = null;
            try { p_prd = getBaselineScan(project_list.SelectedItem.Text, baseline_suffix_p); }
            catch { p_prd = null; }

            string[] p_qa = null;
            try { p_qa = getBaselineScan(project_list.SelectedItem.Text, baseline_suffix_q); }
            catch { p_qa = null; }

            if (project_list.SelectedIndex != 0 && (p_prd != null || p_qa != null))
            {
                alert.Visible = false;
                message.Text = "";
                scans_form.Visible = true;

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
                    CxPortalWebService SOAPservice = new CxPortalWebService();
                    SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                    Regex regex = new Regex(commentsFilterRegEx);
                    log.Info("Comment filtering pattern applied to scans:  " + commentsFilterRegEx);

                    Get_Project_Properties(Int64.Parse(project_list.SelectedItem.Value));
                    CxWSResponseScansDisplayData sdd = SOAPservice.GetScansDisplayData(ViewState["session"].ToString(), Int64.Parse(project_list.SelectedItem.Value));
                    if (sdd != null)
                    {
                        foreach (ScanDisplayData s in sdd.ScanList)
                        {
                            string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                            if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * devScanAge)) > 0 || devScanAge == 0)
                            {
                                Match match = regex.Match(s.Comments.ToString());
                                if ((!match.Success || ignoreFilter) && !s.IsIncremental)
                                {
                                    dt.Rows.Add(false, project_list.SelectedItem.Text, s.ScanID.ToString(), s.Origin.ToString(), s.IsIncremental, getEngineFinishTime(s.ScanID), s.Comments.ToString(), s.IsLocked);
                                }
                            }
                        }
                    }

                    if (p_prd != null)
                    {
                        sdd = SOAPservice.GetScansDisplayData(ViewState["session"].ToString(), Int64.Parse(p_prd[2]));
                        if (sdd != null)
                        {
                            foreach (ScanDisplayData s in sdd.ScanList)
                            {
                                string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                    " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                                if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * baselineScanAge)) > 0 || baselineScanAge == 0)
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
                        sdd = SOAPservice.GetScansDisplayData(ViewState["session"].ToString(), Int64.Parse(p_qa[2]));
                        if (sdd != null)
                        {
                            foreach (ScanDisplayData s in sdd.ScanList)
                            {
                                string datetime = s.FinishedDateTime.Month.ToString("D2") + "/" + s.FinishedDateTime.Day.ToString("D2") + "/" + s.FinishedDateTime.Year +
                                    " " + s.FinishedDateTime.Hour.ToString("D2") + ":" + s.FinishedDateTime.Minute.ToString("D2") + ":" + s.FinishedDateTime.Second.ToString("D2");
                                if (DateTime.Parse(datetime).CompareTo(DateTime.Now.AddDays(-1 * baselineScanAge)) > 0 || baselineScanAge == 0)
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
                        scans_form.Visible = true;
                        alert.Visible = false;

                        prd_latest.DataSource = dtp;
                        prd_latest.DataBind();

                        project_scans.DataSource = dt;
                        project_scans.DataBind();
                    }
                    else
                    {
                        compare.Visible = false;
                        scans_form.Visible = false;
                        alert.Visible = true;
                        if (dt.Rows.Count == 0)
                            message.Text = "There are no development scans to compare.";
                        else if (dtp.Rows.Count == 0 && baselineScanAge == 0)
                            message.Text = "There are no production or QA scans to compare.";
                        else if (dtp.Rows.Count == 0)
                            message.Text = "No baseline scans were run in the last " + baselineScanAge + " days.";
                        else
                            message.Text = "Something went wrong.  Scans for the baseline and development project could not be found. Please contact the administrator.";

                        log.Info(message.Text);
                    }
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                }
            }
            else
            {
                //no scans or no baseline project to compare to
                pdf.Visible = false;
                scans_form.Visible = false;
                compare.Visible = false;
                project_scans.DataSource = null;
                project_scans.DataBind();
                error.Visible = false;
                alert.Visible = true;
                message.Text = "Could not find a corresponding baseline project to compare to.";
            }
        }

        private String getEngineFinishTime(long scanID)
        {
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScanSummary scan = SOAPservice.GetScanSummary(ViewState["session"].ToString(), scanID, true);
                DateTime dt = new DateTime(scan.EngineFinish.Year, scan.EngineFinish.Month, scan.EngineFinish.Day, scan.EngineFinish.Hour, scan.EngineFinish.Minute, scan.EngineFinish.Second);
                if (dt.Year == 1)
                    return "N/A";
                else
                    return formatDate(dt);
            }
            catch(Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                return "N/A";
            }
        }

        protected void projects_SelectedIndexChanged(object sender, EventArgs e)
        {
            getScans();
        }

        private string [] getBaselineScan(string projectname, string ext)
        {
            try
            {
                string baseline_project = projectname.Substring(0, projectname.LastIndexOf("_")) + ext;
                Session["baseline"] = baseline_project;
                return Get_LastScan(baseline_project);
            }
            catch(Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }
        }

        public void SortListControl(ListControl control, bool isAscending)
        {
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
            return String.Format("{0:d} {0:t}", d);
        }

        private string getVersion_OLD(long scanID)
        {
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScansDisplayExtendedData sdd = SOAPservice.GetScansDisplayDataForAllProjects(ViewState["session"].ToString());
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

        protected async void getComparison(string [] scanIDs)
        {
            bool low = lows.Checked;
            DataTable dt = new DataTable();
            dt.Columns.Add(" ", typeof(string));
            dt.Columns.Add("Previous Scan", typeof(string));
            dt.Columns.Add("New Scan", typeof(string));

            long oldscan = Int64.Parse(scanIDs[0]);
            long newscan = Int64.Parse(scanIDs[1]);

            ViewState["ids"] = oldscan + "_" + newscan;

            log.Info(ViewState["user"] + " chose scans:  " + oldscan + ", " + newscan);

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponseScanSummary old_scan = SOAPservice.GetScanSummary(ViewState["session"].ToString(), oldscan, true);
                CxWSResponseScanSummary new_scan = SOAPservice.GetScanSummary(ViewState["session"].ToString(), newscan, true);

                dt.Rows.Add("Scan Risk", old_scan.ScanRisk.ToString(), new_scan.ScanRisk.ToString());
                dt.Rows.Add("LOC", old_scan.LOC.ToString(), new_scan.LOC.ToString());
                dt.Rows.Add("Files Count", old_scan.FilesCount.ToString(), new_scan.FilesCount.ToString());
                dt.Rows.Add("Project Name", old_scan.ProjectName.ToString(), new_scan.ProjectName.ToString());
                dt.Rows.Add("Team", old_scan.TeamName.ToString(), new_scan.TeamName.ToString());
                dt.Rows.Add("Preset", old_scan.Preset.ToString(), new_scan.Preset.ToString());
                dt.Rows.Add("Source Origin", old_scan.Path.ToString(), new_scan.Path.ToString());
                dt.Rows.Add("Scan Type", old_scan.ScanType.ToString(), new_scan.ScanType.ToString());

                string old_version = "", new_version = "";
                try
                {
                    String json = await getVersion(oldscan);
                    dynamic t =  JObject.Parse(json);
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

                foreach(CxWSQueryLanguageState s in old_scan.ScanLanguageStateCollection)
                {
                    old_lang += s.LanguageName + ", ";
                }

                foreach (CxWSQueryLanguageState s in new_scan.ScanLanguageStateCollection)
                {
                    new_lang += s.LanguageName + ", ";
                }

                dt.Rows.Add("Languages", old_lang.Trim().Trim(','), new_lang.Trim().Trim(','));
                dt.Rows.Add("Custom Field Value(s)", ViewState["CustomFields"].ToString() == "" ? " " : ViewState["CustomFields"].ToString(), ViewState["CustomFields"].ToString() == "" ? " " : ViewState["CustomFields"].ToString());

                comparison.DataSource = dt;
                comparison.DataBind();

                scans_form.Visible = false;
                comparison_form.Visible = true;
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
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                log.Info("Old Scan:  " + oldscan);
                log.Info("New Scan:  " + newscan);
                //log.Info(ViewState["session"].ToString());

                CxWSResponseScanCompareSummary scs = SOAPservice.GetScanCompareSummary(ViewState["session"].ToString(), oldscan, newscan);
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

                scans_form.Visible = false;
                comparison_form.Visible = true;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }


            //===========GETRESULTSFORSCAN-NE===============

            DataTable ne = new DataTable();
            //ne.Columns.Add("ID", typeof(string));
            ne.Columns.Add("Query", typeof(string));
            ne.Columns.Add("Count of NEs", typeof(string));
            //ne.Columns.Add("Source File", typeof(string));
            //ne.Columns.Add("Dest File", typeof(string));
            //ne.Columns.Add("Severity", typeof(string));
            //ne.Columns.Add("Comments", typeof(string));

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";

                CxWSResponceScanResults results = SOAPservice.GetResultsForScan(ViewState["session"].ToString(), newscan);
                List<queryName> qsummary = new List<queryName>();
                foreach(CxWSSingleResultData r in results.Results)
                {
                    if (r.State == 1)//not exploitable
                    {
                        string sev = "Informational";
                        switch(r.Severity)
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
                        //if (comment.Contains(project_list.SelectedItem.Text))
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

                foreach(queryName qn in qsummary)
                    ne.Rows.Add(new String[] { qn.name, qn.id.ToString() });

                not_exploitable.DataSource = ne;
                not_exploitable.DataBind();

                scans_form.Visible = false;
                comparison_form.Visible = true;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            //return true;
        }

        private bool checkList(long i)
        {
            foreach(queryName q in names)
            {
                if (q.id == i)
                    return true;
            }
            return false;
        }

        private int checkList(string name, List<queryName> list)
        {
            for(int i = 0; i < list.Count; i++)
            {
                if (list[i].name.Equals(name))
                    return i;
            }
            return -1;
        }

        private string getNameFromList(long i)
        {
            foreach (queryName q in names)
            {
                if (q.id == i)
                    return q.name;
            }
            return "Unknown";
        }

        private string Get_Query_Name(long scanid, long queryid)
        {
            if (checkList(queryid))//if name already found, don't look up again; pull from list
            {
                return getNameFromList(queryid);
            }
            else
            {
                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    CxPortalWebService SOAPservice = new CxPortalWebService();
                    SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                    CxWSResponceQuerisForScan queries = SOAPservice.GetQueriesForScan(ViewState["session"].ToString(), scanid);

                    foreach (CxWSQueryVulnerabilityData q in queries.Queries)
                    {
                        if (q.QueryId == queryid)
                        {
                            names.Add(new queryName(q.QueryName, queryid));
                            return q.QueryName;
                        }
                    }
                    names.Add(new queryName("Unknown", queryid));
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
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService();
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponceResultPath history = SOAPservice.GetPathCommentsHistory(ViewState["session"].ToString(), scanid, pathid, ResultLabelTypeEnum.Remark);

                return history.Path.Comment.Replace("ÿ","[newline]");
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
                return "";
            }
        }

        protected void compare_Click(object sender, EventArgs e)
        {
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

            if (checked_count != 2 || scanIDs[0] == null || scanIDs[1] == null)
            {
                error.Visible = true;
                error.Text = "Please select one PRD/QA scan to compare and one DEV scan to compare.";
            }
            else if (noscanrun)
            {
                error.Visible = true;
                error.Text = "Only production scans skipped due to no code changes detected are allowed.  Please select a different development scan for comparison.";
            }
            else if(DateTime.Compare(baseline, dev) > 0)
            {
                error.Visible = true;
                error.Text = "The baseline scan must be older than the development scan.   Please choose a different baseline scan or run a new development scan.";
            }
            else
            {
                error.Visible = false;
                error.Text = "";
                getComparison(scanIDs);
                pdf.Visible = true;
            }
        }

        private void makePDF()
        {
            log.Info(ViewState["user"] + " generating report.");
            try
            {
                StringWriter sw = new StringWriter();
                HtmlTextWriter output = new HtmlTextWriter(sw);

                log.Info("Adding comparison report.");
                this.panel.RenderControl(output);

                var config = new TheArtOfDev.HtmlRenderer.PdfSharp.PdfGenerateConfig();
                config.SetMargins(25);
                
                config.PageOrientation = PdfSharp.PageOrientation.Landscape;
                if(pagesize.ToLower().Equals("letter"))
                    config.PageSize = PdfSharp.PageSize.Letter;
                else if (pagesize.ToLower().Equals("legal"))
                    config.PageSize = PdfSharp.PageSize.Legal;
                else if (pagesize.ToLower().Equals("tabloid"))
                    config.PageSize = PdfSharp.PageSize.Tabloid;
                else
                    config.PageSize = PdfSharp.PageSize.Letter;
                
                log.Info("Generating PDF.");
                PdfDocument document = PdfGenerator.GeneratePdf(sw.ToString().Replace("<th scope=\"col\">", "<td>").Replace("<\\th>", "<\\td>"), config);

                foreach (PdfSharp.Pdf.PdfPage page in document.Pages)
                {
                    XGraphics gfx = XGraphics.FromPdfPage(page);
                    XFont font = new XFont("Arial", 11, XFontStyle.Regular);
                    gfx.DrawString("  CxGate " + VERSION + " Report | " + DateTime.Now + " | Run by:  " + ViewState["sendto"], font, XBrushes.Black, new XRect(0, 0, page.Width, 20), XStringFormat.TopLeft);
                }

                String filename = ViewState["ids"].ToString() + ".pdf";
                String fullpath = Server.MapPath("~") + "/CxGateReports/" + filename;
                document.Save(fullpath);

                //pdflink.Text = Cxserver + "/CxGate/CxGateReports/" + filename;
                StringBuilder sb = new StringBuilder();
                sb.Append("prompt('The report has been saved.  Copy the report link below to your change request.','" + Cxserver + "/CxGate/CxGateReports/" + filename + "')");
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
            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                e.Row.Cells[1].HorizontalAlign = HorizontalAlign.Center;
            }
        }

        protected void pdf_Click(object sender, EventArgs e)
        {
            try
            {
                makePDF();
            }
            catch(Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }

        protected void goBack_Click(object sender, EventArgs e)
        {
            getScans();
        }

        protected void getlogs_Click(object sender, EventArgs e)
        {
            try
            {
                FileInfo fi = new FileInfo(Server.MapPath("~") + @"\logs\CxGate.log");
                StreamReader sr = new StreamReader(fi.OpenRead());
                string s = "";
                while ((s = sr.ReadLine()) != null)
                {
                    Response.Write(s + "<br/>");
                }//end while
            }
            catch(Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }

        protected void extract_param_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                Process process = new Process();

                TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
                int secondsSinceEpoch = (int)t.TotalSeconds;

                process.StartInfo.FileName = HttpContext.Current.Server.MapPath("~/") + "extract.exe";
                process.StartInfo.Arguments = ViewState["session"].ToString() + " " + extract_param.SelectedValue + " " + ViewState["sendto"] + 
                    " \"" + HttpContext.Current.Server.MapPath("~/") + "reports\\CxExtract_" + secondsSinceEpoch + ".xlsx\" " + Cxserver + " \"" +
                    HttpContext.Current.Server.MapPath("~/") + @"\cxqa.properties" + "\"";

                //log.Info(process.StartInfo.Arguments.ToString());
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;
                process.EnableRaisingEvents = true;
                process.Exited += (psender, args) =>
                {
                    while (!process.StandardOutput.EndOfStream)
                    {
                        string line = process.StandardOutput.ReadLine();
                        log.Info(line);
                    }

                    while (!process.StandardError.EndOfStream)
                    {
                        string line = process.StandardError.ReadLine();
                        log.Info(line);
                    }
                };
                process.Start();

                alert.Visible = true;
                message.Text = "Report has been requested and will be sent to " + ViewState["sendto"] + ".";
            }
            catch(Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
                alert.Visible = true;
                message.Text = "Failed to request the report.  Please contact your administrator.";
            }
        }

        /*REST*/

        private String getRESTToken(String json)
        {
            try
            { 
                dynamic t = JObject.Parse(json);
                return t.access_token;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
            return "ERROR";
        }

        private async Task<string> authREST(String un, String pw)
        {
            try
            {
                HttpClient client = new HttpClient();
                String url = Cxserver + "/cxrestapi/auth/identity/connect/token";
                var values = new Dictionary<string, string>
                {
                    { "username", un },
                    { "password", pw },
                    { "grant_type", "password" },
                    { "scope", "sast_rest_api" },
                    { "client_id", "resource_owner_client" },
                    { "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" }
                };

                var content = new FormUrlEncodedContent(values);
                var response = await client.PostAsync(url, content);
                var responseString = await response.Content.ReadAsStringAsync();

                return responseString;
            }
            catch (Exception ex)
            {
                log.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }

            return "Error";
        }

        private async Task<string> getVersion(long scanID)
        {
            try
            {
                HttpClient client = new HttpClient();
                String url = Cxserver + "/cxrestapi/sast/scans/" + scanID;
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ViewState["RESTTOKEN"].ToString());
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
