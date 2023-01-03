using System;
using OfficeOpenXml;
using System.IO;
using extract.CX;
using System.Data;
using System.Collections.Generic;
using System.Net.Mail;
using System.Net.Http;
using System.Security.Policy;
using System.Linq;
using System.Text;
using System.Net;

namespace extract
{
    class Program
    {
        readonly static string VERSION = "2.1";
        private static log4net.ILog log;
        static string session;
        static string token;
        static string project;
        static string toEmail;
        static string path;
        static bool isProject;
        static string Cxserver;
        static string projectName;
        static string config;
        static FileInfo csvFile;
        static List<String> rows = new List<String>();

        static void Main(string[] args)
        {
            if (args.Length == 6)
            {
                config = args[5];
                Console.WriteLine(config.Substring(0, config.LastIndexOf("\\")) + "\\log4net_extract.config");
                log4net.Config.XmlConfigurator.Configure(new FileInfo(config.Substring(0, config.LastIndexOf("\\")) + "\\log4net_extract.config"));
                log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

                log.Info("Recieved extract request.");
                log.Info("extract v" + VERSION);

                session = "";
                token = args[0];
                project = args[1];
                log.Info("Project / Team:  " + project);
                toEmail = args[2];
                log.Info("Requested by / Send to:  " + toEmail);
                path = args[3];
                Cxserver = args[4];
                try { Int32.Parse(project); isProject = true; }
                catch { isProject = false; }

                log.Info("isProject:  " + isProject);

                if (isProject)
                {
                    log.Info("Getting scan ID.");
                    long scanID = getLastScan(project, null);
                    log.Info("Getting scan results for scan ID:  " + scanID);
                    DataTable t = getScanResults(scanID);
                    log.Info("Building excel file.");
                    buildXLSX(t);
                    log.Info("Sending export to:  " + toEmail);
                    sendMail();
                }
                else //is a team, not a project
                {
                    log.Info("Getting scan results for team:  " + project);
                    csvFile = new FileInfo(path.Replace(".xlsx", ".csv"));
                    try
                    {
                        csvFile.Delete();
                    }
                    catch { }

                    path = csvFile.ToString();
                    log.Info("Building CSV");

                    try
                    {
                        using (StreamWriter sw = new StreamWriter(path, true))
                        {
                            sw.WriteLine("Query,State,Source File,Source Name,Destination File,Destination Name,Query ID,Path ID,Source Line,Destination Line,Deep Link,Project Name,Severity,Query Version,Comments");
                        }

                        foreach (long pid in getProjectsSOAP(project))
                        {
                            try
                            {
                                long scanID = getLastScan(pid.ToString(), project);
                                if (scanID != -1)
                                {
                                    rows.Clear();
                                    //log.Info("Getting scan results for scan ID:  " + scanID);
                                    getScanResultsV2(scanID);
                                    try
                                    {
                                        using (StreamWriter sw = new StreamWriter(path, true))
                                        {
                                            foreach (String s in rows)
                                                sw.WriteLine(s);
                                        }
                                    }
                                    catch (Exception e) { log.Error("Could not write to CSV file.  " + e.Message + Environment.NewLine + e.StackTrace); }
                                }
                                else
                                {
                                    log.Info("No last scan for pid:  " + pid);
                                }
                            }
                            catch (Exception ex)
                            {
                                log.Error("Problem fetching:  " + pid + Environment.NewLine + ex.StackTrace);
                            }
                        }

                        log.Info("Sending export to:  " + toEmail);
                        sendMail();
                    }
                    catch (Exception ex) { log.Error("Problem building CSV for team.  " + ex.Message + Environment.NewLine + ex.StackTrace); }
                }
            }
            else
            {
                Console.WriteLine("version:  " + VERSION);
                log.Info("Not enough parameters supplied to generate Cx extract.  CxGate Extract Version:  " + VERSION);
            }

            log.Info("Extract process completed.");
            Environment.Exit(0);
        }

        private static void sendMail()
        {
            string sendFrom, smtpHost, smtpUsername = "", smtpPassword = "", server;
            bool defaultCred, enableSSL;
            int smtpPort;

            try { server = getProperty("cxserver"); } catch { server = ""; }
            try { sendFrom = getProperty("sendFrom"); } catch { sendFrom = ""; }
            try { smtpHost = getProperty("smtpHost"); } catch { smtpHost = ""; }
            
            try { string temp = getProperty("defaultCred"); defaultCred = Boolean.Parse(temp); } catch { defaultCred = false; }
            try { string temp = getProperty("enableSSL"); enableSSL = Boolean.Parse(temp); } catch { enableSSL = true; }
            try { string temp = getProperty("smtpPort"); smtpPort = Int32.Parse(temp); } catch { smtpPort = 587; }

            if(!defaultCred)
            {
                try { smtpUsername = getProperty("smtpUsername"); } catch { smtpUsername = ""; }
                try { smtpPassword = getProperty("smtpPassword"); } catch { smtpPassword = ""; }
            }

            log.Info($"Mail parameters:  [host:{smtpHost}, port:{smtpPort}, sendFrom:{sendFrom}, smtpUser:{smtpUsername}, defaultCred:{defaultCred}, SSL:{enableSSL}, toEmail:{toEmail}]");

            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient SmtpServer = new SmtpClient(smtpHost);
                mail.From = new MailAddress(sendFrom);
                mail.To.Add(toEmail);
                if(isProject)
                    mail.Subject = "Checkmarx Report for " + projectName;
                else
                    mail.Subject = "Checkmarx Report for " + project;

                path = path.Substring(path.LastIndexOf("\\")+1);

                mail.Body = "Data export is available here:  " + server + "/CxGate/reports/" + path;
                log.Info("Email body:  " + mail.Body);

                //System.Net.Mail.Attachment attachment;
                //attachment = new System.Net.Mail.Attachment(path);
                //mail.Attachments.Add(attachment);

                SmtpServer.Port = smtpPort;

                if (defaultCred)
                    SmtpServer.UseDefaultCredentials = true;
                else
                {
                    SmtpServer.UseDefaultCredentials = false;
                    SmtpServer.Credentials = new System.Net.NetworkCredential(smtpUsername, smtpPassword);
                }

                SmtpServer.EnableSsl = enableSSL;

                log.Debug(mail.ToString());

                SmtpServer.Send(mail);
            }
            catch(Exception ex)
            {
                log.Error("Problem sending email.  " + ex.Message + Environment.NewLine + ex.StackTrace);
                Environment.Exit(-1);
            }
        }

        // FIXME: Add Json deserialization lib
        /*
        private List<long> getProjectsInTeam(long teamId)
        {
            List<long> projectIds = new List<long>();

            try
            {
                String endpoint = "/cxrestapi/projects?teamId=" + teamId;

                HttpResponseMessage httpResponse = REST_GET(endpoint, token, null);
                String responseString = httpResponse.Content.ReadAsStringAsync().Result;
                if (httpResponse.IsSuccessStatusCode)
                {
                    dynamic projects = JsonConvert.DeserializeObject(responseString);
                    foreach (var p in projects)
                    {
                        String pid = p.id.ToString();
                        projectIds.Add(int.Parse(pid));
                        log.Info("Project added to list to pull last scan:  [" + pid + "] " + p.name.ToString());                        
                    }
                }
                else
                {
                    log.Error("GET call to [" + endpoint + "] returned HTTP " + httpResponse.StatusCode + ". " + responseString);
                }
            }
            catch (Exception e)
            {
                log.Error(e.Message + Environment.NewLine + e.StackTrace);
            }

            return projectIds;
        }
        */





        private static List<long> getProjectsSOAP(string group)
        {
            List<long> pIDs = new List<long>();

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(token);
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseProjectsDisplayData projects = SOAPservice.GetProjectsDisplayData(session);
                foreach (ProjectDisplayData p in projects.projectList)
                {
                    if (group.ToUpper().Equals(p.Group.ToUpper()))
                    {
                        pIDs.Add(p.projectID);
                        log.Info("Project added to list to pull last scan:  [" + p.projectID + "] " + p.ProjectName);
                    }
                }

            }
            catch(Exception ex)
            {
                log.Error("Problem getting projects." + Environment.NewLine + ex.StackTrace);
            }

            return pIDs;
        }

        private static DataTable getScanResults(long scanID)
        {
            DataTable table = new DataTable();
            try
            {
                //log.Info("Getting queries for scan:  " + scanID);
                List<(long, string)> queries = getQueriesForScan(scanID);
            
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(token);
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponceScanResults sr = SOAPservice.GetResultsForScan(session, scanID);

                table.Columns.Add("Query Name");
                table.Columns.Add("State");
                table.Columns.Add("Source File");
                table.Columns.Add("Source Name");
                table.Columns.Add("Dest File");
                table.Columns.Add("Dest Name");
                table.Columns.Add("QueryID");
                table.Columns.Add("PathID");
                table.Columns.Add("Source Line");
                table.Columns.Add("Dest Line");
                table.Columns.Add("Deep Link");
                table.Columns.Add("Project Name");
                table.Columns.Add("Severity");
                table.Columns.Add("Query Group");
                table.Columns.Add("Comment");

                foreach (CxWSSingleResultData d in sr.Results)
                {
                    string severity = "Unknown"; string state = "Other"; string queryName = "Unknown";
                    switch (d.Severity.ToString())
                    {
                        case "0":
                            severity = "Informational";
                            break;
                        case "1":
                            severity = "Low";
                            break;
                        case "2":
                            severity = "Medium";
                            break;
                        case "3":
                            severity = "High";
                            break;
                    }

                    switch (d.State.ToString())
                    {
                        case "0":
                            state = "To Verify";
                            break;
                        case "1":
                            state = "Not Exploitable";
                            break;
                        case "2":
                            state = "Confirmed";
                            break;
                        case "3":
                            state = "Urgent";
                            break;
                        case "4":
                            state = "Proposed Not Exploitable";
                            break;
                    }

                    string deeplink = Cxserver + "/CxWebClient/ViewerMain.aspx?scanid=" + scanID + "&projectid=" + project + "&pathid=" + d.PathId;

                    string[] comment = d.Comment.Split('ÿ');

                    foreach ((long, string) o in queries)
                    {
                        if (o.Item1 == d.QueryId)
                        {
                            queryName = o.Item2;
                            break;
                        }
                    }

                    table.Rows.Add(new String[] { queryName, state, d.SourceFile, d.SourceObject, d.DestFile, d.DestObject, d.QueryId.ToString(), d.PathId.ToString(),
                                                d.SourceLine.ToString(), d.DestLine.ToString(), deeplink, projectName, severity, d.QueryVersionCode.ToString(), comment[0] });
                }

            }
            catch(Exception ex)
            {
                log.Error("Problem getting scan results." + Environment.NewLine + ex.StackTrace);
            }
            return table;
        }

        private static void getScanResultsV2(long scanID)
        {
            try
            {
                //log.Info("Getting queries for scan:  " + scanID);
                List<(long, string)> queries = getQueriesForScan(scanID);

                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(token);
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponceScanResults sr = SOAPservice.GetResultsForScan(session, scanID);

                foreach (CxWSSingleResultData d in sr.Results)
                {
                    string severity = "Unknown"; string state = "Other"; string queryName = "Unknown";
                    switch (d.Severity.ToString())
                    {
                        case "0":
                            severity = "Informational";
                            break;
                        case "1":
                            severity = "Low";
                            break;
                        case "2":
                            severity = "Medium";
                            break;
                        case "3":
                            severity = "High";
                            break;
                    }

                    switch (d.State.ToString())
                    {
                        case "0":
                            state = "To Verify";
                            break;
                        case "1":
                            state = "Not Exploitable";
                            break;
                        case "2":
                            state = "Confirmed";
                            break;
                        case "3":
                            state = "Urgent";
                            break;
                        case "4":
                            state = "Proposed Not Exploitable";
                            break;
                    }

                    string deeplink = Cxserver + "/CxWebClient/ViewerMain.aspx?scanid=" + scanID + "&projectid=" + project + "&pathid=" + d.PathId;

                    string[] comment = d.Comment.Split('ÿ');

                    foreach ((long, string) o in queries)
                    {
                        if (o.Item1 == d.QueryId)
                        {
                            queryName = o.Item2;
                            break;
                        }
                    }

                    String[] rowvalues = new String[] { queryName, state, d.SourceFile, d.SourceObject, d.DestFile, d.DestObject, d.QueryId.ToString(), d.PathId.ToString(),
                                                d.SourceLine.ToString(), d.DestLine.ToString(), deeplink, projectName, severity, d.QueryVersionCode.ToString(), comment[0] };

                    String row = String.Empty;
                    foreach (String s in rowvalues)
                        row += quote(s);

                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                log.Error("Problem getting scan results." + Environment.NewLine + ex.StackTrace);
            }
        }

        private static String quote(String s)
        {
            if (s.Length > 0)
                return "\"" + s + "\",";
            else
                return "";
        }

        private static List<(long, string)> getQueriesForScan(long scanID)
        {
            List<(long, string)> queries = new List<(long, string)>();

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(token);
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponceQuerisForScan qfs = SOAPservice.GetQueriesForScan(session, scanID);

                foreach (CxWSQueryVulnerabilityData q in qfs.Queries)
                    queries.Add((q.QueryId, q.QueryName));
            }
            catch(Exception ex)
            {
                log.Error("Problem getting query names." + Environment.NewLine + ex.StackTrace);
            }

            return queries;
        }

        private static long getLastScan(string projectID, string teamName)
        {
            try
            {
                log.Info("Getting last scan for " + projectID + "/" + teamName);
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                CxPortalWebService SOAPservice = new CxPortalWebService(token);
                SOAPservice.Url = Cxserver + "/CxWebInterface/Portal/CxWebService.asmx?WSDL";
                CxWSResponseScansDisplayData sdd = SOAPservice.GetScansDisplayData(session, Int64.Parse(projectID));
                foreach (ScanDisplayData d in sdd.ScanList)
                {
                    if (teamName == null)
                    {
                        projectName = d.ProjectName;
                        return d.ScanID;
                    }
                    else
                    {
                        string SOAPteamname = "";
                        try
                        {
                            SOAPteamname = d.TeamName;
                        }
                        catch (Exception ex2)
                        {
                            log.Error("Problem getting SOAP Team Name. [" + projectID + "/" + teamName + "]" + Environment.NewLine + ex2.StackTrace);
                        }

                        if (SOAPteamname.ToUpper().Equals(teamName.ToUpper()))
                        {
                            try
                            {
                                projectName = d.ProjectName;
                            }
                            catch (Exception ex2)
                            {
                                log.Error("Problem getting project Name. [" + projectID + "/" + teamName + "]" + Environment.NewLine + ex2.StackTrace);
                            }

                            long scanID = -1;
                            try
                            {
                                scanID = d.ScanID;
                            }
                            catch (Exception ex2)
                            {
                                log.Error("Problem getting scan ID. [" + projectID + "/" + teamName + "]" + Environment.NewLine + ex2.StackTrace);
                            }

                            return scanID;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log.Error("Problem getting last scan." + Environment.NewLine + ex.StackTrace);
            }

            return -1;
        }

        private static void buildXLSX(DataTable table)
        {
            try
            {
                using (ExcelPackage excel = new ExcelPackage())
                {
                    excel.Workbook.Worksheets.Add("Cx Extract");
                    var worksheet = excel.Workbook.Worksheets["Cx Extract"];
                    worksheet.Cells.LoadFromDataTable(table, true);

                    var range = worksheet.Cells["A1:O1"];
                    range.AutoFilter = true;
                    range.Style.Font.Bold = true;

                    worksheet.Cells[worksheet.Dimension.Address].AutoFitColumns();

                    FileInfo excelFile = new FileInfo(path);
                    excel.SaveAs(excelFile);
                }
            }
            catch (Exception ex)
            {
                log.Error("Problem building Excel report." + Environment.NewLine + ex.StackTrace);
            }
        }

        private static string getProperty(string property)
        {
            try
            {
                string[] lines = System.IO.File.ReadAllLines(config);

                foreach (string line in lines)
                {
                    if (line.StartsWith(property))
                    {
                        return line.Split('|')[1];
                    }//end if
                }//end foreach
            }//end try
            catch (Exception ex)
            {
                log.Error("Problem getting SMTP property:  " + property + Environment.NewLine + ex.Message + Environment.NewLine + ex.StackTrace);
                Environment.Exit(-1);
            }//end catch

            return "";
        }

        // FIXME: JSON serialization
        /*
        private HttpResponseMessage REST_POST(String endpoint, string bearerToken, Dictionary<string, string> parameters)
        {
            endpoint = endpoint.StartsWith("/") ? endpoint : ("/" + endpoint);
            String url = Cxserver + endpoint;

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + bearerToken);

            String json = parameters == null ? String.Empty : JsonConvert.SerializeObject(parameters);

            log.Debug("Executing POST " + url + " with " + json);

            StringContent content = new StringContent(json, Encoding.UTF8, "application/json");
            return client.PostAsync(url, content).Result;
        }
        private HttpResponseMessage REST_GET(String endpoint, string bearerToken, Dictionary<string, string> parameters)
        {
            endpoint = endpoint.StartsWith("/") ? endpoint : ("/" + endpoint);
            if (parameters != null)
            {
                endpoint += string.Join("&", parameters.Select(kvp => $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value.ToString())}"));
            }
            String url = Cxserver + endpoint;

            log.Debug("Executing GET " + url);

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + bearerToken);

            return client.GetAsync(url).Result;
        }
        */
    }
}
