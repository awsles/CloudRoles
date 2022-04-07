# Scripts
This folder contains the scripts that are used to manage and apply the role definitions.
 
# AWS
For AWS, the script **Set-AwsRole.ps1** is used to push role (policy) definitions into AWS accounts.
The script prompts the user to select the role definition file(s)
(which are in JSON format -- see README.md at https://github.com/ConnectedHomes/CloudRoles/tree/master/AWS).
The script reads in a list of accounts (a CSV file for now) and allows the administrator 
to select which AWS accounts to push the definitions to.  Multiple roles may be pushed into multiple accounts.

## Prerequisites
In order for the script to 'push' configuration into another AWS account, each target account must 'trust'
the production security account (XXXXXXXXXXXX) and/or the Master account
and have the role **CloudBootstrapper** defined and enabled.

The script also requires the full list of AWS accounts in '**aws_accounts.csv** in the same directory
as the script with the 1st line exactly as '*AccountNumber,AccountName,RoleNamePrefix,Owner*'.
Each subsequent line contains comma-separated data for the respective columns.
The RoleNamePrefix is the AWS role name prefix (e.g., '**Prod-Security-**') with the trailing dash.
The role name (as created by the script) will then pre-append that string to form the name
(e.g., '**Prod-Security-CloudDeveloper**').

Note that it will still be necessary to create the corresponding AD group, which needs to
follow the prescribed form so that SAML mapping works 

### Setting up CloudBootstrapper
In order to push role definitions and other configuration into an AWS account, you must first create
the **CloudBootstrapper** role.  The steps to do this are as follows:

1. Sign in [here](TBD) into the target AWS account using a CloudAdmin role.
2. Navigate to the IAM service and select **Policies** in the left side menu [here](https://console.aws.amazon.com/iam/home?region=us-east-1#/policies).
3. Create the policy definition for **CloudBootstrap**:
    1. Click the blue **Create Policy** button at top.
    2. Click the JSON tab.
    3. Cut and paste the contents of the **CloudBootstrap.json** file (WITHOUT the //Comments).
    4. Click the blue **Review Policy** button at bottom.
    5. Enter the name **CloudBootstrap** with the description "Cloud policy for bootstrapping AWS account configuration."
    6. Click the blue **Create Policy** button at the bottom.
4. Create the **CloudBootstrap** role using the above policy definition.
    1. Click the "Roles" option in the left side menu.
    2. Click the blue **Create Role** button.
    3. Select the type of trusted entity as "Another AWS account".
    4. Enter the account ID "XXXXXXXXXXXX" (this is the Cloud Production Security account).
    5. Tick the "Require external ID (Best practice when a third party will assume this role)" option.
    6. Enter the External ID as "XXXXXXXXXXXX".
    7. Do NOT tick the "Require MFA" option.
    8. Click the blue **Next: Permissions**" button.
    9. Search for "CloudBootstrap" and tick the box to it's left.
    10. Click the blue **Next: Tags** button.
    11. Add a tag:  Key="Createby" and Value="{your full name}"
    12. Click the blue **Next: Review** button.
    13. Enter the Role Name as "CloudBootstrap".
    14. Enter the Role Description as "Cloud role for bootstrapping AWS account configuration."
    15. Click the blue **Create Role** button.
5. Verify that the role is defined. 
  
Once the **CloudBootstrapper** role has been created, configuration may be pushed from account XXXXXXXXXXXX.
The script **Set-AwsRole.ps1** is used to push additional role definitions into the target AWS account.


# Azure
For Azure, the script **Set-AzureRole.ps1** is used to push role definitions into Azure. Unlike AWS, the role
definitions are defined tenant-wide and then selectively enabled on a per-subscription basis.
The script prompts the user to select the role definition file(s)
(which are in JSON format -- see README.md at https://github.com/ConnectedHomes/CloudRoles/tree/master/AZURE).
The script allows the administrator to select which Azure subscriptions to enable the role definitions in.
This is done by adding the subscription to the policy scope. Multiple roles may be pushed into multiple accounts.

