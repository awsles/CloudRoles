# AZURE Role Definitions
This folder contains the definitions for Microsoft Azure.

Most 'people' roles definitions are standardized across all Azure subscriptions.
This ensures consistency in the rights and permissions granted by each role.
For example, a 'Cloud Network Admin' has exactly the same set of rights in each Azure subscription.

Note, however, the scope at which the role is assigned my vary. In most cases, roles are
assigned at the subscription level, meaning that the role has rights over the entire subscription.
In some cases, a role is applied at the Resource Group level or (less frequently) on a specific resource.

## One-Off Definitions
Where a special permission is required for a particular individual or team, an appropriately named role
is created for that individual (or group) and then assigned to the selected users (or group).
The role definition should ONLY grant the additional rights and SHOULD NOT clone an existing standard definition.

For example, if a 'Cloud Developer' requires access to a new service which is normally blocked,
then a separate role definition may be created for that service and then linked to a new or existing role.
Alternatievly (recommended approach) is to use an existing built-in policy and link it to the existing role.
This makes it clear what the additional rights are for the role.

If there are multiple requests for the same rights, it may be time to incorporate the right into one
of the standard Cloud policy definitions.  A balanced risk-based approach should be used when making
this decision (i.e., balances the risk of the additional right vs. managing one-offs).

## JSON Format
Each role is defined in a seperate JSON document, typically named **azure-\<*RoleName*>.json**.
The role definition follows the AWS format BUT also may contain additional properties
(such as PolicyName and PolicyDescription) and may also contain embedded comments.

Comments may be inserted using '//'. The double slashes and anything after it on each line is
stripped by the associated tools before the JSON is converted into an object.

An example Azure role definition:

<pre>
// Cloud Sample Network Role
// Grants read access to everything and full access to Networking and network tracing on all resources.
// This role is typically only assigned to network personnel.
//
{
    "Name":  "Cloud Network Admin",
    "Id":  "00000000-0000-0000-0000-000000000000",  // ID of EXISTING role definition (if new, leave as "")
    "Description":  "Grants global read access and full access to Networking and network tracing on all resources.",
    "Actions":
    	[
		"*/read",
		"Microsoft.Resources/*",
		"Microsoft.Networks/*",
		"*/networktrace/action"
    	],
    "NotActions":
	[

	],
    "DataActions":
	[

	],
    "NotDataActions":
	[

	],
    "AssignableScopes": [],		// Omit or leave blank (not used when applying definition via script)
    "DefaultUserAssignments": []	// AD groups which should be assigned to the role by default
}
</pre>

## Service Principal / Automation Roles
Automation processes should be assigned their own role custom role definitions commensurate with the privileges required.
A SINGLE custom definition should be created for the role and that definition enabled within the applicable Azure subscriptions
using the AssignableScopes property of the custom role definition (vs. creating a separate definition within each subscription).
This ensures that the role definition is correct and consistent across all accounts which use the role
(i.e., across DevTest, PreProd, and Prod).

A separate service principal instance should be used for production vs. non-production for security purposes.

### For Further Information...
For more information, please contact Lester Waters or Paul Neyton.
