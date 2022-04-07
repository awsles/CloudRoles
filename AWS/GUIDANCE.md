# AWS Guidance
This document provides some basic guidance for the development and deployment
of AWS RBAC policy, roles, and users.

## How to create a Service role
Developers in AWS DevTest environments have the ability to define RBAC policies and attach
them to service roles, which can be assumed by users.
Ideally, policy, role, and even user creation should be part of the automated build and deploy pipeline process.
Manual creation is discouraged.

### Resource Naming
Where possible, resources should be named the same across devtest, preprod, and prod. 
This is less error-prone where automation is used and means you don’t have to have conditionals
in the terraform (or other) automation and/or have to sync multiple automation scripts.
Note that the above contravenes existing naming conventions.

For resources where the name must be globally unique such as for S3 resources,
use "-d-" (devtest) and "-p-" (prod), etc. within the resource name.
Use a single character wildcard (e.g., "… **-?-** …") in the **Resources:** section of the policy
which effectively allows any single character.
On the surface, this will appear to allow access to the S3’s in the other accounts but for that to work,
you have to explicitly allow the S3 to trust the other account.
In summary, you won’t be able to cross the account boundary even with a "-?-" in the resources section.

### Determining Necessary Permissions
There are several approaches to determining the permissions necessary for a service principal / role.

The first approach is to grant broad permissions to the role by service area: for example "s3:*" or "ecs:*".
After a period of testing for a week or so, the AWS console can be consulted to see which permissions
have been used and which have not been used. This information can then be used to further tune the
role to follow the principle of least privilege (i.e., the role only has those permissions that are required,
and ideally only for those resources that the role needs to touch).

An alternative approach is to estimate the RBAC permissions needed for the role and assign those
up front. Any permission issues which are encountered can then be recitified by immediately updating
the role's permissions in the DevTest environment.  This approach is iterative in nature.
Before moving into PreProduction, the AWS console can be consulted to see which permissions
have not been used, and rmeove those accordingly.

### Pipeline Role
When using automation such as Azure DevOps (ADO) or Terraform, it will be necessary to have a "pipeline" role
(e.g., "ADO-pipeline-role") and policy  (e.g., "ADO-pipeline-policy"). The pipeline process will use
the role via sts:AssumeRole in order to do the build.  The pipeline role will need to have sufficient privileges
in order to accomplish the build, including any permissions necessary for created additional IAM roles and
policies required for deployed services.

At this time, developers will need to engage the Cloud Engineering team in order to deploy / update a pipeline role.
In the future, a "pipeline-admin" role *may* be created which allows editing of the role and policy by appropriate individuals.

## How to create a Service (User) Account
In addition to role creation, developers in AWS DevTest environments also have the ability to create local userst
*for the purpose of service principal user*. Developers MUST NOT create roles for their own use, without
consulting the cloud operations team.  Doing so may result in forfeiture of the right to create any user accounts.

### Boundary Permissions
All service roles and users created by developers MUST have the **CloudServiceBoundary** boundary policy
attached. Creation or updates without this policy will fail for developers.

