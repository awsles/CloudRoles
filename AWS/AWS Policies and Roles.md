# AWS Policies and Roles
One of the first steps in securing an AWS accounts is creating proper role definitions
which not only meet the needs of the business, but also reasonably satisfy
the principles of *least privilege* and *segregation of duty*. 
Sometimes, these principles are treated as laws, resulting in an excessive
number of policy definitions, increased management overhead (forever updating different polices as AWS
services evolve), and a different kind of increased risk.

## Account Segregation
In a larger enterprise, you may have 50 or even 100+ AWS accounts. I strongly recommend that
separate AWS accounts be established for:
1) Development/Test ("DevTest") 
2) Pre-Production / Staging
3) Production

This will allow you to have different roles and policies, based on the account's purpose.

## Standardize Your Policy Definitions
Some people prefer to use the built-in AWS policies to associate with roles and users.
In practice though, I have found that the AWS standard policy definitions are often too 
vertical in nature, and so multiple policicies have to be combined to achieve the desired effect.
And remember, there is a limit of 10 policies that can be associated to any single role or user.
Also, the AWS **ReadOnlyPolicy** lacks quite a few services.

I tend to prefer creating custom roles which better align to business and security needs.
My recommendations include:

* Creating custom policy definitions which align to business and security needs.
* Standardize the policy definitions across all accounts (e.g., a "Developer" policy has the
exact same permissions in every account).
* Use a common policy name prefix such as your company name. This will allow you to conditionally
protect those policy definitions in a boundary policy.
* Put your policy JSON documents into an internal GIT repository so that they can be governed.
* Automate the deployment of policy documents and roles. Personally, I wrote a PowerShell
script which allows me to select policy documents and push them to multiple AWS accounts
(note that it does some minimal account number substitutions as needed).
* Standardize your policy and role naming convention.
* Never define a policywith an 'AWS' prefix. Such poliies are typically created by AWS, so avoid using
anything that looks like AWS may have created it.
* Enable AWS Organizations and aall of the features therein.
* Implement a [Service Control Policy (SCP)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html).
Note that this requires AWS organizations to be enabled and configured.
* Attach a boundary policy to user and role definitions. (more on this below)
* Avoid granting AdministratorAccess, except to a trusted few.
* Avoid using groups for "highly privileged" roles, especially Active Directory groups used for SAML role access.
Groups are frequently exploited for privilege escalation. If you do need to use groups, make sure they are very secure.
* Do not define policies and roles with different names based on environment / account purpose. If a custom policy is used across a DevTest, Staging, and Production accounts, it should have the same name throughout.
* It's OKAY to include conditional access rules in policies which apply to multiple accounts. For example, you may have an S3 named mydev1 in your DevTest account; another S3 named mystage1 in your staging account; and a 3rd S3 naed myprod1 in production. You can have all three in a conditional access policy statement, so that you can have a single policy document used across all accounts. Remember, conditional access does NOT itself grant cross-account access - so having a statement of such in a policy document poses no risk.


## Boundary Policies
I strongly recommend attaching a [boundary policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
to users and role definitions. The boundary policy should re-iterate any restrictions of the SCP as a precaution
but also include any further restrictions.  The boundary policy can be used to:

* Restrict access to any CloudWatch, CloudTrail, and GuardDuty resources which being with "Security". This will allow your security team to set up monitoring actions which cannot be tampered with.
* Restrict changes to the boundary policy itself.
* Restrict changes to any standardized policy and role definitions.
* Protect other key actions like tampering with route tables (i.e., you may want the default route for all traffic to
go to your firewall rather than to the internet - no one should tamper with that).

## Role and User Management
One of the business challenges for a security practitioner is letting go of **some** policy, role, and even user management.
There are AWS services, such as AWS Connect, which, when deployed, will also deploy policy and role definitions.
Also, many of the AWS templates will do the same.
Your developers *in a development account* should be reasonably free to deploy such services and not be encumbered by IAM restrictions.
Of course, this can be quite tricky to get right.
In the development environment, the developer policy is permitted to create policies at will.
But a policy can only be attached to a role or user IF the role or user has a specific named boundary policy attached.

In tuning your standardized roles, you will receive requests from developers for certain permissions.
Either something that was overlooked, or a new service or permission which AWS has introduced.
I encourage the developer to put forward the JSON changes they would like to see. This forces
the developer to better understand policy definitions and to figure out the exact permissions required.

## Drive Automation
Although developers may be given broad permissions *in a development account*, they
should focus on building and deploying using some form of automation, whether it be
an AWS CloudFormation template, a tool such as Terraform, or Azure DevOps, or even a PowerShell or bash script.
The reason is two-fold: (a) In the event of a disaster, or even a need to redeploy into another AWS region,
re-building by hand is not effective - and is VERY error prone; and (b) deployment automation ensures consistency of deployment
and forces developers to consider their actions.

A good way to enforce this is to severely limit access in Staging and Production accounts.
The ONLY way a deployment can be done is through an automation user/role, which has sufficient rights.
Note that such rights can be revoked after a service goes live for an added measure of safety.

## Standardize your Role Definitions
Similar to policies, your assumable roles should be standardized.

* Use a common role name prefix such as your company name. This will allow you to conditionally
protect those role definitions in a boundary policy.
* Keep your role definitions tied to the same policy definitions across all accounts.
* Attach custom extensions
* Never define a role with an 'AWS' prefix. Such roles are typically created by AWS, so avoid using
anything that looks like AWS may have created it.
* If a specific permission is required in one account, create (or use a built-in) separate policy for that permission
and attach it to the role. For example, you may not normally grant CDN permissions, but may wish to
allow it as an exception.

User roles (used for cloud interactive login) should have standardized role definitions (naming and permissions) across
all AWS accounts, respectively. This serves to minimize the number of customized role
definitions which have to be managed. It also allows for centralized management of the common user roles, complete
with automation for pushing changes to such roles out to all AWS accounts and Azure subscriptions.

It is important to note that the roles below relate to cloud management activities and are NOT
specific to data access (although some roles will include a level of data access). Data access roles are
outside the scope of this document. The policy documents associated are prefixed with "COMPANY".

### General Roles
Below are some roles that I typically like to deploy. But this will depend on the way business and engineering
activities are conducted at your COMPANY.

:white_check_mark: **Cloud Administrator** -- Provides full administrative access including user access management rights.

:white_check_mark: **Reader** -- Provides read-only access to virtually all cloud configuration and many operating metrics.
This goes beyond the AWS built-in **ReadOnlyAccess** policy.

:white_check_mark: **Network Administrator** -- Provides administrative access to all networking capabilities and selected other
administrative capabilities for use by the networking team. 

:white_check_mark: **Firewall Operator** -- Provides administrative capability to all security groups, cloud network ACLs, and
PaaS firewalls so that firewall rules may be managed. This is a subset of the Network Administrator capabilities.

:white_check_mark: **Security Administrator** -- Provides administrative access to security functions for use by the COMPANY Security team.

:white_check_mark: **Security Operator** -- Provides limited security operator access for use by COMPANY Security operations.

:white_check_mark: **Service Administrator** -- Provides limited administrative access to resources, allowing for starting and
stopping of VMs, limited reconfiguration capability, tag management, and more. Does not permit user access management.

:white_check_mark: **Troubleshooter** -- Provides full read access to configuration data, service metrics, and most logs.
Also enables some very limited operational actions such as VM start/stop, volume snapshotting, and diagnostics configuring.
Typically, this is the follow-on role for developers in the Pre-Production and production environments. It is also suitable for assignment to quality assurance / test personnel.


### Optional Roles
Lastly, there are a number of roles which are optional, and may only be suitable for certain applications
(for example, the "Data Scientist" role).

:black_square_button: **Full Stack Developer** -- Allows access to most (but not all) network-related cloud services
such as load balancers, firewalls, subnets, etc. Specifically excluded are VPC/VNET creation, VPNs, Express Networking, CDNs,
and route table management. This role allows selected developers to prototype new services and define firewall rules in a
more agile fashion. Developer are expected to follow COMPANY network design patterns and engage the appropriate team(s)
for any deviations thereof.

:black_square_button: **Data Scientist** -- Allows creatation and running of queries on Hadoop, MapReduce, and data lakes
for the purposes of big data analytics.

:black_square_button: **User Access Admin** -- Allows configuring of user access permissions within the respective
AWS account or Azure subscription. This role is currently only created if it is required for a specific account / subscription. Use this role if your IAM activities are really segregated.


### Data Access Roles
The aforementioned roles relate to cloud management plane permissions (although some management permissions have a degree
of data tier access). Data plane roles are typically defined within each specific service. For example, Microsoft SQL
and AWS RDS both have roles and permissions which are defined within the service itself.
The management and governance for such roles is outside the scope.

### Build Pipeline User
Every deployment should have a build pipeline user that is defined in DevTest, staging, and production.
The role allows the build pipeline (such as Azure DevOps, Teraform, etc.) tha ability to build and deploy services.
The build pipeline user is a local AWS user account which typically has a lot of privileges, including the ability
to create users, roles, and policies.

In production environment as an added security measure, the pipeline role can be temporarily disabled by simply removing the authorization credential. This has the net effect of ensuring that no one runs a new pipeline or inadvertently accesses the role.
When it is necessary to run the pipeline to deploy into production again, a new credential can be generated
and configured into the deployment tool.

#### Azure DevOps
For Azure DevOps, create a policy named "*AzureDevOps-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*AzureDevOps-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

#### Terraform
For Terraform, create a policy named "*Terraform-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*Terraform-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

Teraform can be used to deploy AWS policy, roles, and users.
See: https://www.terraform.io/docs/providers/aws/guides/iam-policy-documents.html

#### Jenkins
For Jenkins, create a policy named "*Jenkins-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*Jenkins-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

Jenkins can use AWS CodeDeploy to deploy policies, roles, and users.

### Built-In Roles
Both AWS and Azure have a number of built-in RBAC roles and policies. In AWS, some of the built-in policies are used as part of the COMPANY role definitions. For example, the *COMPANYNetworkAdministrator* role is created using the NetworkAdministrator built-in policy, combined with the COMPANYNetworkAdministrator and the COMPANYReader policies. In Azure, the RBAC permissions are incorporated directly into the role definitions. For example, the Azure Reader role is directly assigned to users.


---
## Useful Resources
Below are some useful tools and resources which may help in securing role access in your AWS accounts.

* [Principal Mapper (pmapper)](https://www.nccgroup.trust/uk/our-research/principal-mapper-pmapper/)
-- This tool uses the existing simulator APIs to determine which users and roles have access to each other.
It provides a query interface on top of this data and can help fid prvilege escalation paths.

