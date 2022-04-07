# Role Governance

This github repository contains the permission definitions for the various user and service principal (automation) roles 
in both AWS and Azure.

## General Principles
There are a few general principles by which role definitions and chanages therein shall be governed. These are (in no particular order):

:small_blue_diamond: More rights for Developers in DevTest; far fewer rights in PreProd and Production.

:small_blue_diamond: Use a balanced approach to *Principle of Least Privilege* based on risk and manageability (i.e., don't overdo least privilege).

:small_blue_diamond: Infrastructure as Code to enable Automated Deployments for application-specific roles, policies, and service accounts.

:small_blue_diamond: Maintain a 1:1 relationship between AD groups and cloud roles. For Azure, in most cases, this means defining a  custom role definition for each user role.

:small_blue_diamond: User roles (i.e., those roles for interactive logins) shall have standardized permissions across all Azure subscriptions and AWS accounts, respectively. This ensures consistency when referring to each role.

:small_blue_diamond: Service account roles shall reasonably follow the *Principle of Least Privilege* and have rights specific to the respective application needs.

:small_blue_diamond: Policy, role, and user names (including service roles) should be consistently named across all environments, *regardless of the environment type* (i.e., avoid using prefixes or suffixes denoting "DevTest", "PreProd", "Prod", etc.). Renaming for each different environment adds unnecessary complexity to the build process and runs the risk of introducing errors. For example, if you have a service account for ODBC access, give the role an appropriate name such as “ODBC-Access-Role” which could have a corresponding policy “ODBC-Access-Policy”. 

:small_blue_diamond: Most user roles are controlled through active directory group memberships. In AWS, this may be a single AD group which is specifically mapped by SAML. Limited delegated management of such AD groups shall be available to respective DevOps teams.
Note that for highly privileged administrative roles , the use of AD groups is discouraged - users should be directly assigned the role.

:small_blue_diamond: Where a permissions exception is absolutely required, a *separate* AWS Policy or Azure Role definition shall be created within the respective AWS account or Azure subscription. For AWS, the custom policy may then be attached to the appropriate role (such as to Developer role), or may be deployed as a separate assumable role. For Azure, the custom role is then attached to the assigned users / groups.

## Custom Policies, Roles, and Users
Most applictaion deployments will require some degree of custom roles, policies, and user (service) accounts. 
In order to maintain agility and efficiency, developers are given more ability to define limited roles required for their respective application deployments. The expectation is that such roles shall be deployed uisng a build & deploy pipeline (vs. being manually built). This ensures rapid recovery for any production applictaion which has to be rebuilt or re-deployed in a recovery situation.

In general, custom policy and role definitions will NOT be maintained in this GitHub, as those respective definitions
should be kept within the associated built pipeline repository. However, sample definitions for reference purposes may be found in
the **AWS/Examples** and the **AZURE/Examples** folders.

* Application-specific policy, roles, and users SHOULD be deployed via the automation pipeline. This can be Teraform, Cloud Formation, a script, or whatever. This encourages a deployment template which essentially builds everything required for the application – ideal for supporting rapid recovery (who wants to raise tickets or chase people to rebuild roles, which could be error prone?). The Build pipeline process will have sufficient permissions to accomplish policy, role, and user deployments in each environment. 
* Policies for service account users SHOULD be configured as an in-line policy (i.e., embedded within the user definition rather than a separate stand-alone policy). This keeps the scope of the policy tightly coupled with the user definition. A separate stand-alone policy MAY be used when it serves multiple purposes.
* All application-specific roles and users MUST have the “ServiceBoundary” policy attached. Create and update actions will fail with permissions errors if this is not the case.
* There is no stringent naming convention for AWS policies, roles, or users. However, the names should reasonably reflect the respective purpose. The following are specifically blocked and reserved for Cloud Engineering use: AWS policies, roles, users, AWS CloudWatch alarms and dashboards, or CloudTrail names MUST NOT begin with the "cloud", "aws", or "security".
* Developers MUST NOT create local AWS user account for their own purposes (e.g., for CLI access) without first consulting the Cloud Engineering team. Once permission is granted, the local AWS username MUST match the email address of the user. 
* All application-specific AWS roles and users SHOULD have a tag “CreatedBy” along with the name of the individual who created the role. Other tags should be applied in accordance with the cloud naming and tagging standard.
* All AWS user account credentials MUST be stored securely in compliance with the company Password Standard. KeePass is one recommended tool of choice. Where credential sharing is necessary, TEAMS may be used to send the secret component, after which the message thread should be deleted by both the sender and recipient.
* The pipeline credentials for the production environment SHOULD be separate from those used in DevTest and PreProd (which may share a service principal). This includes cases where the build is using sts:AssumeRole.
* Abuse of the generous rights granted via the Developer role, and build pipeline accounts will result in a reduction of privileges. Don’t create accounts for personal use (including faux service accounts) without first consulting cloud operations.
* The CostCenter tag may only be set ONCE. Once in place, it cannot be updated or deleted. You will need to engage Cloud Engineering to change this.
* SIDs in AWS Policies SHOULD have the last 10 digits as YYYYMMDD (e.g., "AllowLimitedIAM20190819") to reflect the last edit date of the associated json section. Updating of this MAY be done automatically when code is checked into GitHub and a change is detected (TBD if this is possible).
* Billing data SHALL (eventually) BE stored into a read-only S3 bucket within each AWS account (as well as being forwarded) whose name begins with 'AWSBilling' and includes all or part of the AWS Account Number.
* Users and Roles SHOULD be tagged with the AWS Resource Group name with which they are associated.
* Pipelined policy, role, and user creation MUST be appropriately reviewed and approved (i.e., by Cloud Engineering or IT Security), prior to any deployment into production, as well as early in the development process, and when any significant changes are made therein.
* HLTD documents SHOULD include a brief summary of the anticipated roles, service account users, and associated policies, and respective purpose for each.

### Teraform
To create policy, roles, and users via Teraform, see:

:link: AWS Policy: https://www.terraform.io/docs/providers/aws/guides/iam-policy-documents.html

:link: AWS Roles: https://www.terraform.io/docs/providers/aws/r/iam_role.html

:link: AWS Users: https://www.terraform.io/docs/providers/aws/d/iam_user.html


## User Role Governance
For both Azure and AWS,  user role definitions are stored in this repository in an augmented JSON format.
JSON does not provide an ability to have arbitrary comments.  The format used herein treats any text after
double forward slashes (//) or double backslashes (\\) as a comment.
The automation scripts herein will strip comments from the file before applying the changes to the target cloud environment.
In some cases, it may be desirable to cut & paste a definition into a web portal interface (e.g., AWS policy definitions).
In this case, all comments must be manually edited out before saving.

Note that automation role definitions are typically NOT stored in this respository.  Rather, the definitions
should be stored within the respository for the associated project as the role definition is expected to
be different for each project.

Using the JSON format for role definitions ensure a consistent format for the roles which is easily editable.
Anyone with write access to the repository may submit proposed role changes (but not directly into the MASTER branch). 
The submissions should be placed into a branch based on the submittor's github username.
When the user is ready to submit his or her change for consideration, the user generates a "pull"
request (effectively meaning "*Please PULL my changes into the MASTER branch*").

When a PULL request is received, the approval team (e.g., someone each from Security, Operations, and Cloud Architecture)
can review the request, view the changes (or newly proposed role). Once approved, an admin can
accept the pull request and merge the changes into the MASTER branch.

At this point, someone in Operations or Security can "push" the role to the appropriate accounts / subscriptions
using one of the scripts provided herein or through a manual process.
At a future date, this could take place automatically, triggered on approved changes into the MASTER branch.

### Reviewers
The team of reviewers are as follow:

* Cloud Service Operations
* IT Security 
* Cloud Architecture


### Roles under Development
Roles which are under development may be tested in the AWS accounts or Azure subscriptions which have been
agreed by the Reveiewers team. As a role nears production readiness, the role definitions may be pushed to
all AWS accounts / Azure subscriptions but then only made available on a limited basis (to begin with).

In some cases, selected developers may be given the ability to define roles themselves (but not to attach them).

## Delegated Membership Management
Delegated management of *selected* Active Directory groups
associated with an application is permitted. Through delegation, a nominated team member such as a
development lead or a project manager may be granted the right to directly manage an Active Directory group.

Roles available for delegated management include: Reader, Developer, Troubelshooter, Data Scientist, Service Admin, Virtual Machine Operator, Service Operator, Pipeline Developer, and Deployment Manager. Network-specific roles such as Network Admin, and Firewall Operator are delegated to a member of the T&N team (typically Matt Ford). IT Security related roles such as Cloud Auditor, Security Admin, and Key Vault Admin may be delegated to a member of the IT Security team. Cloud Admin and User Access Admin roles cannot be delegated to mode 2 team (these roles are manage by Cloud Ops / Cloud Engineering team only).

### Managing an AD Group
The membership of an Active Directory group may be managing using RSAT tools or by starting a **cmd** prompt
and entering the following (recommended approach):

``
    rundll32 dsquery,OpenQueryWindow
``

and then search for the appropriate AD group. 

You can edit membership if you are the owner and the tick box has been checked to allow editing by the owner.
Or if it’s your PRV account that has ownership, then at the CMD prompt:

``
    runas /user:uk\PRV-account "rundll32 dsquery,OpenQueryWindow"
``

If the group is mail-enabled (most cloud groups are not), then membership may be editable via Outlook:
https://www.ucl.ac.uk/isd/how-to/modify-central-distribution-list-members-outlook-2016-for-windows


## Background
It is  important to understand how AWS and Azure each implement roles. 

### Amazon Web Services (AWS)
Access in AWS is controlled by creating policies and attaching them to Identity and Access Management (IAM) identities
(users, groups of users, or roles) or AWS resources within each AWS account.
An IAM policy is a (JSON) object in AWS that, when associated with an identity or resource, defines its permissions
(what actions it can and cannot perform).
AWS evaluates these policies when a principal entity (user or role) makes a request. Permissions in the policies
determine whether the request is allowed or denied. Most policies are stored in AWS as JSON documents.
AWS supports six types of policies: 
identity-based policies, resource-based policies, permissions boundaries, Organizations SCPs, ACLs, and session policies.

In AWS, these posicies may be edited using a tick-box oriemted web-based interface, or by editing the JSON directly.
AWS policies may have conditionals attached, including scoping rules.
Each policy must be defined in each AWS accoiunt in which the policy is to be used (i.e., attached to a user, role, or resource).

More AWS information on Policies and Permissions may be found [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).

### Microsoft Azure
In Azure, policy is typically edited via PowerShell cmdlets as there is no suitable web interface. 
Azure uses "role definitions" which simply define the permissions (actions and notactions) for the role.
A role definition is then made available to Azure subscriptions by adding each subscription to the "AssignableScopes" for the role.
Essentially, this means that the role definition is *available* for assignment within that subscription.
Assignments may be made at the subscription, resource group, or resource-specific level within Azure.

Unlike AWS, a role assignment in Azure includes the scope at which the role is assigned to the selected user or service principal.
In AWS, the scope is defined within the particular RBAC policy.

Detailed Microsoft information about Azure role definitions may be found [here](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-definitions).

