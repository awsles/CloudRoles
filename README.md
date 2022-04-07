# CloudRoles
This respository contains the role / policy definitions for AWS and Azure along with associated tools.

# Standard Roles
User roles (used for cloud interactive login) shall have standardized role definitions (naming and permissions) across
all Azure subscriptions and AWS accounts, respectively. This serves to minimize the number of customized role
definitions which have to be managed. It also allows for centralized management of the common user roles, complete
with automation for pushing changes to such roles out to all AWS accounts and Azure subscriptions.

It is important to note that the standard roles herein relate to cloud management activities and are not
specific to data access (although some roles will include a level of data access). Data access roles are
outside the scope.

Within the standard user roles, roles are either Mandatory, Recommended, or Optional.
Most roles are available in all environments. However, a few roles are only available in select environments
(for example, developer roles are only available in development and build pipeline environments).

Note that the role names vary slightly, depending on cloud platform. For example, AWS does not permit spaces in role names,
so the actual names as it appears within AWS will have spaces removed.
Furthermore, role names in AWS may be prefixed by the environment and AWS account name.

Within AWS, the permissions associated with a role are defined in Policy, whereas in Azure, thet are defined by roles.
In both cloud environments, the names are all share a common prefix, which is usually "Cloud".


### Why Use Custom Roles?
Custom role definitions allow for better alignment with company security and infrastructure management goals and standards.
The default roles provided by Azure, AWS, and GCP are often far too generic and assume a relatively open environment.
Many companies want to enable a self-service culture, so long as the guardrails are in place to limit those
self-service capabilities. For example, a developer should be permitted to deploy a new virtual machine, but should not
be permitted to attach a public IP address to it, or toalter routing tables.

The tradeoff is that custom roles do require a degree of maintenance, primarily to add new rights and services
as they are requested.

### Custom Role Scope
For consistency within Azure cloud, it is highly recommended that the mandatory custom roles be deployed at the root management group level.
The optional or environment-specific roles should also be deployed via management groups, relative to the Azure subscription.

For AWS, roles (policies) are always defined at the account level.


## Core Roles
There are core roles which SHOULD appear in every AWS account and Azure subscription. These include:

:white_check_mark: **Cloud Admin** -- Provides full administrative access including user access management rights.

:white_check_mark: **Cloud Reader** -- Provides read-only access to virtually all cloud configuration and many operating metrics.
This reader role may provide specific limitations (or additions) aligned to company standards and practices.

:white_check_mark: **Cloud Network Admin** -- Provides administrative access to all networking capabilities and selected other
administrative capabilities for use by the networking team.

:white_check_mark: **Cloud Firewall Operator** -- Provides administrative capability to all security groups, cloud network ACLs, and
PaaS firewalls so that firewall rules may be managed. This is a subset of the Network Admin capabilities.

:white_check_mark: **Cloud Security Admin** -- Provides administrative access to security functions for use by IT Security.

:white_check_mark: **Cloud Security Operator** -- Provides limited security operator access for use by IT Security operations.

:white_check_mark: **Cloud Service Admin** -- Provides limited administrative access to resources, allowing for starting and
stopping of VMs, limited reconfiguration capability, tag management, and more. Does not permit user access management.

:white_check_mark: **Cloud Troubleshooter** -- Provides full read access to configuration data, service metrics, and most logs.
Also enables some very limited operational actions such as VM start/stop, volume snapshotting, and diagnostics configuring.
Typically, this is the follow-on role for developers in the Pre-Production and production environments. It is also suitable for assignment to QA / test personnel.


## Optional Roles
In addition to the mandatory roles, there are roles which should also be included in many, if not most, circumstances.
Some roles may only be suitable for certain applications (e.g., "Cloud Data Scientist" role).
These are:

:ballot_box_with_check: **Cloud Security Auditor** -- Allows limited access to security auditing functions. This role may soon be deprecated as it may be replaced by the *Security Operator* role. 

:ballot_box_with_check: **Cloud Developer** -- Allows administration of many cloud services, excluding most networking aspects.
Users in this role may build, deploy, and manage virtual machines and other cloud services. 

:ballot_box_with_check: **Cloud Full Stack Developer** -- Allows administration of most (but not all) network-related cloud services
such as load balancers, firewalls, subnets, etc. Specifically excluded are VPC/VNET creation, VPNs, Express Networking, CDNs,
and route table management. This role allows selected developers to prototype new services and define firewall rules in a
more agile fashion. Developer are expected to follow T&N design patterns and engage T&N for any deviations thereof.

:ballot_box_with_check: **Cloud Database Admin** -- Allows administration of most data and database PaaS services.

:ballot_box_with_check: **Cloud Pipeline Developer** -- Enables building of deployment pipelines. Can build and delete most things.

:ballot_box_with_check: **Cloud Virtual Machine Operator** -- Allows starting & stopping of virtual machines and configuring of Insights rules and Resource Health actions.

:ballot_box_with_check: **Cloud Locks Admin** -- Allows configuring of resource locks (Azure only).

:ballot_box_with_check: **Cloud Resource Group Contributor** -- Allows management of resource groups, role assignments within the resource group, policy assignments, and resource locks (Azure only).
Useful for environments where resource group creation is controlled (not a recommended practice).

:ballot_box_with_check: **Cloud Key Vault Admin** -- Allows management of Key Vaults (including the secrets within), storage account keys, and most other keys.

:ballot_box_with_check: **Cloud Data Scientist** -- Allows creatation and running of queries on Hadoop, MapReduce, and data lakes
for the purposes of big data analytics.

:ballot_box_with_check: **Cloud BackupAdmin** -- Allows administrative access to VMs for the purposes of backup administration.

:ballot_box_with_check: **Cloud User Access Admin** -- Allows configuring of user access permissions within the respective
AWS account or Azure subscription. This role is currently only created if it is required for a specific account / subscription.


## Data Access Roles
The aforementioned roles relate to cloud management plane permissions (although some management permissions have a degree
of data tier access). Data plane roles are typically defined within each specific service. For example, Microsoft SQL
and AWS RDS both have roles and permissions which are defined within the service itself.
The management and governance for such roles is outside the scope of this repository.


## Service Roles / Service Accounts
In addition to the mandatory user roles above, there are several service raccount oles / user principals which may be required in some or all
AWS accounts / Azure subscriptions. These may be required for operational and security purposes. These include:

:arrow_down_small: **Cloud Auditor** -- Provides full read access to configuration and logging data and includes
limited capability to control audit and logging functions. In AWS, this is an assumable role from the Security account.
In Azure, this is a User Service Principal.

:arrow_down_small: **Bootstrap** -- This is an AWS IAM-specific role with a specific trust relationship
which allows creation of other roles within the respective AWS account. This roles is used by the Security
production account in lieu of the administrative role created via AWS Organizations.

### Build Pipeline User
Every deployment should have a build pipeline user that is defined in DevTest, pre-production, and production.
The role allows the build pipeline (such as Azure DevOps, Teraform, etc.) tha ability to build and deploy services.
The build pipeline user is a local AWS user account which typically has a lot of privileges, including the ability
to create users, roles, and policies.

The recommended practice for creating this role is to use the Developer role to create the user and
associated policy. The *principle of least privilege* should be reasonably followed when defining the pipeline role.
For example, if your pipeline has no need for itself to create users, or define roles, or policy, then it should
not have the rights to do so. Other permissions can be granted a bit more liberally where the service is to
be deployed by the pipeline (e.g., "ec2:*", "s3:*", etc.).  The pipeline user should have sufficient rights to
update and/or remove existing configurations.

**IMPORTANT:** As with any role or user created by a Developer, it MUST have the *CloudServiceBoundary* policy attached as
a boundary policy to the respective user / role.  If your build pipeline requires the ability to itself create roles and users
as part of the build and deploy process, then please consult with IT Security or Cloud Engineering to have the
boundary policy removed from the pipeline user.

In production environment as an added security measure, the pipeline role can be temporarily disabled by simply removing the authorization credential. This has the net effect of ensuring that no one runs a new pipeline or inadvertently accesses the role.
When it is necessary to run the pipeline to deploy into production again, a new credential can be generated
and configured into the deployment tool.

#### Azure DevOps
For Azure DevOps, create a policy named "*ADO-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*ADO-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

#### Terraform
For Terraform, create a policy named "*Terraform-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*Terraform-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

Teraform can be used to deploy AWS policy, roles, and users.
See: https://www.terraform.io/docs/providers/aws/guides/iam-policy-documents.html

#### Jenkins
For Jenkins, create a policy named "*Jenkins-Pipeline-Policy*" with appropriate permissions and then attach it to
a new user named "*Jenkins-Pipeline*". Including a prefix or suffix with the environment type is NOT recommended.

Jenkins can use AWS CodeDeploy to deploy policies, roles, and users.

## Built-In Roles
Both AWS and Azure have a number of built-in RBAC roles and policies. In AWS, some of the built-in policies are used as part of the custom cloud role definitions. For example, the *CloudNetworkAdmin* role is created using the NetworkAdministrator built-in policy, combined with the NetworkAdmin and the CompanyReader policies. In Azure, the RBAC permissions are incorporated directly into the role definitions. For example, the Azure Reader role is directly assigned to users.


## Authoritative Definitions
The cloud provider specific definitions for the preceding roles and associated policiesy are maintained as 
commented JSON files within this GitHub repository. Consult the respective application cloud folder.

The authoritative definition for AWS roles (including the list of attached policies and associated Active Directory group)
may be found in the AWS-Roles.json file
in the AWS folder in this repository.  For Azure, the roles are defined by the role definitions in the AZURE folder
of this repository (there is no need for a master list as roles in Azure are defined differently).

---
## References

* List of Azure Services - https://github.com/leswaters/AzureServices
* List of AWS Services - https://github.com/leswaters/AwsServices


