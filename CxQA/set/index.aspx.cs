using System;
using CredentialManagement;

namespace CxQA.set
{
    public partial class index : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            this.Title = "CxGate 1.0";
        }

        protected void submit_click(object sender, EventArgs e)
        {
            try
            {
                CredentialUtil.RemoveCredentials("checkmarxgate");
                CredentialUtil.SetCredentials("checkmarxgate", username.Text, password.Text, PersistanceType.Enterprise);
                result.Text = "Credential successfully updated.";
            }
            catch (Exception ex)
            {
                result.Text = ex.Message;
            }
        }//end submit_click
    }
}//end CxQA.set