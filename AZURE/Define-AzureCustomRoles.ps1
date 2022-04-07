#Requires -Version 5
<#
.SYNOPSIS
	Creates or updates the Cloud custom RBAC role definitions.
.DESCRIPTION
	This script updates the Cloud custom role definitions across the selected tenants
	and subscriptions. 
	
	For each role, this script will look in all subscriptions within the tenant to see if
	the role is already defined.  If the role is not defined within the tenant, then it is created.
	
	These roles may be deployed at the selected subscription level, but it is highly recommended that
	these roles be defined at the Root Management Group level, so that the roles are consistently defined
	throughout the subscriptions within the tenant.
	
.PARAMETER Rename
	If specified, then the user is prompted for the new name for each existing role chosen.
	
.PARAMETER AddAssignment
	If specified, then the selected subscription(s) are added to the existing scope assignments.
	
.PARAMETER DeleteAssignment
	If specified, then the selected subscription(s) are removed to the existing scope assignments.
	
.PARAMETER ReplaceAssignment
	If specified, then the existing scope assignments are fully replaced in the selected subscription(s).
	
.PARAMETER DefineRole
	If specified, then the role definition is defined/updated. If the role does not exist, it is created.
	This may be specified concurrently with -AddAssignment or -ReplaceAssignment.
	If neither is specified, then the existing assignments are retained when the role is updated.
	If the role is a new role, then you must specify one of the options for assignment.
	
.PARAMETER UpdateScope
	This will update the scope assignment for the selected roles. This is the same as -ReplaceAssignment
	
.PARAMETER CloudAuditor
	If specified, then the 'App_CloudAuditor' service principal is assigned to any subscription
	where the 'Cloud Auditor' role is defined (if the assignment does not already exist).
	This option may not be used with any other option!
	
.PARAMETER Check
	If specified, then the status of each selected subscription is checked. This is slow but
	is useful when there are subscriptions in unusual states.
	
.PARAMETER List
	If specified, then existing custom roles are listed. No update is performed.
	
.PARAMETER All
	If specified, then all roles are updated.  Otherwise, the user is prompted to select the roles to update.
	
.PARAMETER WhatIf
	If specified, then the update is not actually performed.
	
.NOTES
	Author: Lester Waters
	Version: v0.58
	Date: 13-Jul-21
	
	To see a complete list of RBAC capabilities, execute the following PowerShell:
	   Get-AzProviderOperation | Out-GridView

	TO DO:
		- Add ability to view and assign via Management Groups.  This can be a list with subscription selection.
		- $Role.AssignableScopes.Add("/providers/Microsoft.Management/managementGroups/<management group ID>")
		
	LinkedAuthorizationFailed: - Set-AzRoleDefinition fails when existing role has non-existant Scopes
	CATEGORY: Azure ACtive Directory - Domains & Objects
	SUBJECT: LinkedAuthorizationFailed error in Set-AzRoleDefinition
	PROBLEM TYPE: RBAC
	PROBLEM SUBTYPE: Problems with RBAC role assignments
	DESCRIPTION:
	The Set-AzRoleDefintion PowerShell cmdlet fails with a LinkedAuthorizationFailed error when an existing role definitions 
	has a role assignment to a no-longer-existant subscription.
	This is a known problem which occurs when a subscription is deleted but a role definition still has it within the AssignableScopes.
	See Previous Tickets: 119081522000532, 119050221001810, 118111925002106, 118080618729136.

	The solution is to have Microsoft engineering manually remove the subscription assignments.
	Please REMOVE the following subscription IDs from the role definition 'Cloud Auditor' with ID: 00000000-0000-0000-0000-000000000000:

		/subscriptions/00000000-0000-0000-0000-000000000000

	The above subscription(s) no longer exist and the Set-AzRmRoleDefinition fails because of this. The debug output is below.
	This problem has now been around for MANY YEARS and I have submitted many tickets now for this. This is now FINALLY fixed!
	   
.LINK
	https://feedback.azure.com/forums/911473-azure-management-groups/suggestions/34391878-allow-custom-rbac-definitions-at-the-management-gr
	https://docs.microsoft.com/en-us/azure/governance/management-groups/overview#custom-rbac-role-definition-and-assignment
	       e.g. "AssignableScopes": [ "/providers/microsoft.management/managementGroups/ContosoCorporate" ]
			  
#>

# +=================================================================================================+
# |  PARAMETERS																						|
# +=================================================================================================+
[cmdletbinding()]   #  Add -Verbose support; use: [cmdletbinding(SupportsShouldProcess=$True)] to add WhatIf support
Param 
(
	[Parameter(Mandatory=$false)] [switch] $AddAssignment		= $false,		# If true, then add an assignment
	[Parameter(Mandatory=$false)] [switch] $DeleteAssignment	= $false,		# If true, then delete an existing assignment
	[Parameter(Mandatory=$false)] [switch] $ReplaceAssignment	= $false,		# If true, then replace all assignments
	[Parameter(Mandatory=$false)] [switch] $DefineRole			= $false,		# If true, then only update the definitions
	[Parameter(Mandatory=$false)] [switch] $UpdateScope			= $false,		# If true, then update the scope assignment	
	[Parameter(Mandatory=$false)] [switch] $CloudAuditor		= $false,		# If true, then assign Cloud Auditor the role	
	[Parameter(Mandatory=$false)] [switch] $List				= $false,		# If true, then list all custom roles
	[Parameter(Mandatory=$false)] [switch] $Rename				= $false,		# If true, then prompt to rename roles
	[Parameter(Mandatory=$false)] [switch] $Check				= $false,		# If true, then check the state of each selected subscription
	[Parameter(Mandatory=$false)] [switch] $NewRole				= $false,		# If true, then treat as a new role
	[Parameter(Mandatory=$false)] [switch] $All					= $false,		# If true, then all subscriptions and tenants
	[Parameter(Mandatory=$false)] [switch] $WhatIf				= $false		# 
)

# Determine if -verbose was specified
$Verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

# Replace below by using parameter constructs above -- TBD
$msg1	= "Please choose either -AddAssignment, -DeleteAssignments, -ReplaceAssignment, -DefineRole, or -list"
if ($CloudAuditor)
	{ ; }
elseif ($AddAssignment -And $DeleteAssignment)
	{ write-warning $msg1 ; Return $null }
elseif ($AddAssignment -And $ReplaceAssignment)
	{ write-warning $msg1 ; Return $null }
elseif ($DeleteAssignment -And $ReplaceAssignment)
	{ write-warning $msg1 ; Return $null }
elseif (!$AddAssignment -And !$DeleteAssignment -And !$ReplaceAssignment -And !$DefineRole -And !$List -And !$UpdateScope)
	{ write-warning $msg1 ; Return $null }

if ($DefineRole -And $DeleteAssignment)
	{ write-warning "The -DeleteAssignment option cannot be used with -DefineRole" ; return $null }
	

# +=================================================================================================+
# |  EXTERNAL SCRIPTS																				|
# +=================================================================================================+

# Get Current directory (PowerShell scripts seem to default to the Windows System32 folder)
$invocation 	= (Get-Variable MyInvocation).Value
$directoryPath 	= Split-Path $invocation.MyCommand.Path
[IO.Directory]::SetCurrentDirectory($directorypath)   	# Set current directory

# Load the script using DOT notation
# . "$directoryPath\AzureFunctionLibrary.ps1"				# Provides output libraries


# +=================================================================================================+
# |  CONSTANTS																						|
# +=================================================================================================+

# App_CloudAuditor (Service Principal)
$CloudAuditor_AppId		= '00000000-0000-0000-0000-000000000000'
$CloudAuditor_ObjectId	= '00000000-0000-0000-0000-000000000000'	# Service Principal Object ID
# $CloudAuditor_ObjectId	= (Get-AzureAdServicePrincipal -SearchString "App_CloudAuditor" | Where-Object {$_.AppId -like $CloudAuditor_AppId} ).ObjectId
$CloudAuditor_RoleID		= '00000000-0000-0000-0000-000000000000'

# List of preferred subscription IDs where the script will look for role definitions first
$PreferredSubscriptionIDs = @()
$PreferredSubscriptionIDs += '00000000-0000-0000-0000-000000000000'     # Preferred Subscription ID 

# DefaultSubscription -- Use this to find the role definition first (for performance improvment)
$DefaultSubscriptionId = ""				# Security

# Miscellaneous
$crlf 					= [char]13 + [char]10


# +=================================================================================================+
# |  CLASS DEFINITIONS																				|
# +=================================================================================================+

class CustomRole
{
	[string]		$Name
	[string]		$Id
	[string]		$SubName					# Subscription Name in which definition was found
	[string]		$Description
	[string]		$Definition					# ACTION + Role + crlf
	[string]    	$Scopes
	[system.array]	$subscriptionList
	[string]		$Assignees
}

class Tenant
{
	[string]	$Name
	[string]	$Id
	[string]	$Description
}


# +=================================================================================================+
# |  FUNCTIONS																						|
# +=================================================================================================+
function Create-NewRoleDefinition
{
param
(
	[Parameter(Mandatory=$true)]  [string] $Name = "",
	[Parameter(Mandatory=$false)] [string] $Description = ""
)
	$EmptyRole				= Get-AzRoleDefinition -Name "Reader"
	$EmptyRole.Name 		= $Name
	$EmptyRole.Description	= $Description
	$EmptyRole.IsCustom		= $true
	$EmptyRole.Id			= $null
	
	$EmptyRole.Actions.Clear()
	$EmptyRole.NotActions.Clear()
	$EmptyRole.DataActions.Clear()
	$EmptyRole.NotDataActions.Clear()
	$EmptyRole.AssignableScopes.Clear()
	
	return $EmptyRole
}

#
# Check each operation and see if the operation exists
# 
# GLOBAL VARIABLE: $ProviderOperations
#
function Check-ProviderOperations
{
param
(
	[Parameter(Mandatory=$true)]  [PSObject] $CustomRole
)

# Loop through .Actions, .NotActions, .DataActions, .NotDataActions
# Output warnings for anything not found

	write-verbose "Checking Provider Operations for role '$($CustomRole.Name)'..."

	$Result = $True							# No errors
	$CombinedActions = @()
	$CombinedActions += $CustomRole.Actions
	$CombinedActions += $CustomRole.NotActions
	$CombinedActions += $CustomRole.DataActions
	$CombinedActions += $CustomRole.NotDataActions
	
	foreach ($action in $CombinedActions)
	{
		$Matched = $false
		if ($action.Contains('*'))
		{
			# $action1 = $action.SubString(0, $action.IndexOf('*')+1)  # OLD approach: If a wildcard '*' is specified, then truncate and do a startswith
			foreach ($operation in $ProviderOperations.Operation)
			{
				if ($operation -Like $action)
					{
						$Matched = $true;
						# write-verbose "    ACTION: '$Action'   MATCHED Operation: '$Operation'"		# DEBUG
						break;
					}
			}
		}
		else
		{
			$Matched = ($ProviderOperations.Operation -Contains $action)
			# write-verbose "    ACTION: '$Action'   has a match in Provider Operations: $Matched"  # DEBUG
		}

		# Output warning if we didn't match
		if (!$Matched)
		{
			write-warning "No matching provider operation found for '$action' - Please revise the '$($CustomRole.Name)' role definition"
			$Result = $False
		}
	}
	
	return $Result
}

	 
# +=================================================================================================+
# |  MAIN BODY																						|
# +=================================================================================================+
$RoleDefinitions = @()					# Array of all custom roles
$Results = @() 

# Get Sign-In Name
# We should be running as a global admin with User Access Admin capabilities
if (!$List)
{
	write-warning $("**IMPORTANT** This tool should NOT be run unless you have sufficient rights to modify ALL applicable subscriptions!`n" +  `
					"                       i.e., You should be a Global Admin with full subscription view capability enabled.")
}

# +---------------------------------------------+
# |  Get a list of Providers and operations		|
# +---------------------------------------------+
# We do this because the list changes so frequently  (.Operation)
$ProviderOperations = Get-AzProviderOperation


# +---------------------------------------------+
# |  Get list of subscriptions we can see		|
# +---------------------------------------------+
$AllSubscriptions = Get-AzSubscription
$AllEnabledSubscriptions = $AllSubscriptions	| Where-Object {$_.State -like "Enabled"} `
												| Sort-Object -Property Name `
												| Select-Object -Property Name, Id, TenantId, State


# +---------------------------------------------+
# |  Select Tenant (if more than one found)		|
# +---------------------------------------------+
$Tenants = ($AllEnabledSubscriptions | Select-Object -Property TenantId -unique)
if ($Tenants.Count -gt 1)
{
	write-host -ForegroundColor Yellow -NoNewLine "Please choose the TENANT [see popup]: "
	$Tenants = $Tenants | Select-Object -Property TenantId | Out-Gridview -Title "Please choose the TENANT:" -Passthru
	write-host ""
	if ($Tenants.Count -eq 0) { return $null }
}
$tenant = $Tenants[0].TenantId
write-Verbose "TenantID: $tenant"


# +---------------------------------------------+
# |  Select subscription(s)						|
# +---------------------------------------------+
$AllEnabledSubscriptions = $AllEnabledSubscriptions	| Where-Object {$_.TenantId -like $tenant -And $_.State -like "Enabled"} `
										| Sort-Object -Property Name


# +---------------------------------------------+
# |  Remove any WEIRD subscriptions				|		
# +---------------------------------------------+
# NOTE: NOT IN USE AT THIS TIME!!!
$AllEnabledSubscriptions2 = @()
foreach ($sub in $AllEnabledSubscriptions)
{
	if (($sub.Name -Notlike '*Azure Active Directory') -And `
		($sub.Name -Notlike 'Visual Studio*') -And `
		($sub.Name -NotLike 'Free Trial'))
	{
		$AllEnabledSubscriptions2 += $sub
	}
}


# +---------------------------------------------+
# |  App_CloudAuditor							|
# +---------------------------------------------+
$FullCheck = $true		# Verify every subscription... (slow!)
if ($CloudAuditor)
{
	# Get Current Role Assignable Scopes for Cloud Auditor
	# NOTE: Assignable Scopes onbly defines that the role is eligible for assignment.
	# It is still necessary to assign the role to the specific application!
	# $RoleAssignment = Get-AzRoleAssignment -ObjectId $CloudAuditor_ObjectId
	$role = Get-AzRoleDefinition -Id $CloudAuditor_RoleID	
	$success = [int32] 0
	$failure = [int32] 0
	# Progress Counter
	$ctr = [int32] 0
	$Activity = "Provisioning Access to App_CloudAuditor"
	foreach ($sub in $AllEnabledSubscriptions)
	{
		$pctComplete = [string] ([math]::Truncate((++$ctr / $AllEnabledSubscriptions.Count)*100))
		$Status1 = "Subscription: '$($sub.Name)' ($($sub.Id)) - $pctComplete% Complete  ($ctr of $($AllEnabledSubscriptions.Count))"
		Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1	
		write-host -ForegroundColor Yellow -NoNewLine "Subscription: "
		write-host "$($sub.Name)   ($($Sub.Id))"
		
		$Err1 = $null
		if ($role.AssignableScopes -NotContains "/subscriptions/$($sub.id)")
		{
			write-host -ForegroundColor White "   Assigning 'Cloud Auditor' role to App_CloudAuditor..."
			if ($WhatIf)
			{
				write-host -ForegroundColor Cyan "    WhatIf: New-AzRoleAssignment"
			}
			else
			{
				write-verbose "Selecting Subscription..."
				if (!$FullCheck) { $x = Select-AzSubscription -Subscription $sub.id -ErrorAction Stop }
				write-verbose "Updating Assignable scopes..."
				New-AzRoleAssignment -ObjectId $CloudAuditor_ObjectId -RoleDefinitionId $CloudAuditor_RoleID `
								-Scope "/subscriptions/$($sub.Id)" -ErrorAction Continue -ErrorVariable Err1
				# And assign the role to the App_CloudAuditor...	
				Start-Sleep -Seconds 10		# Need to delay so AssignableScope shows up...
				write-verbose "Assigning role to App_CloudAuditor"
				$x = New-AzRoleAssignment -ObjectId $CloudAuditor_ObjectId -Scope "/subscriptions/$($sub.id)" -RoleDefinitionId $CloudAuditor_RoleID
			}
		}
		if (!$err1) { $success++ } else { $failure++ }
		
		# Select subscription and get Role Assignment
		if ($FullCheck)
		{
			# Select Subscription
			$x = Select-AzSubscription -Subscription $sub.id -ErrorAction Stop 
			
			$ra = Get-AzRoleAssignment -ObjectId $CloudAuditor_ObjectId -ErrorAction Continue `
					| Where-Object {$_.Scope -like "/subscriptions/$($sub.id)" -And $_.RoleDefinitionId -like $CloudAuditor_RoleID}

			# See if App_CloudAuditor has been given the 'Cloud Auditor' role
			# If it hasn't, then assign it.
			if (!$ra)
			{
				write-host -ForegroundColor White "   Assigning 'Cloud Auditor' role to App_CloudAuditor..."
				if (!$WhatIf)
				{
					write-verbose "Assigning role to App_CloudAuditor"
					$x = New-AzRoleAssignment -ObjectId $CloudAuditor_ObjectId -Scope "/subscriptions/$($sub.id)" -RoleDefinitionId $CloudAuditor_RoleID
				}
			}
		}
	}
	write-host -ForegroundColor Yellow "$success successful assignments and $failure failures."
	write-Progress -Activity $Activity -PercentComplete 100 -Completed
	return;
}


# +---------------------------------------------+
# |  See which options are chosen by user		|
# |  and prompt to select subscriptions			|
# +---------------------------------------------+
$SelectedSubscriptionIDs = @()
if ($DefineRole -And !$AddAssignment -And !$ReplaceAssignment -And !$UpdateScope)
{
	write-host -ForegroundColor Yellow "Existing custom role definitions will be updated without changing any scope assignments."
	$subscriptions = @()
	$SelectedSubscriptionIDs = $PreferredSubscriptionIds		# Look here first...
}
elseif ($All)
{
	$subscriptions = $AllEnabledSubscriptions 	| Where-Object {$_.TenantId -like $tenant -And $_.State -like "Enabled"} `
										| Sort-Object -Property Name `
										| Select-Object -Property Name, Id, TenantId, State
}
else
{
	write-host -ForegroundColor Yellow -NoNewLine "Please choose the subscriptions [see popup]: "
	$subscriptions = $AllEnabledSubscriptions 	| Where-Object {$_.TenantId -like $tenant -And $_.State -like "Enabled"} `
										| Sort-Object -Property Name `
										| Select-Object -Property Name, Id, TenantId, State `
										| Out-Gridview -Title "Please choose the subscription(s):" -Passthru
	$SelectedSubscriptionIDs += $Subscriptions.Id		# Needs to be an array even if only one subscription chosen...
	write-host ""
	if ($subscriptions.Count -eq 0) { return $null }
}

# Sort the Subscriptions so that we process the ones the user selected first (to improve performance)
# We use the set of subscriptions without the weird ones for the second part
$SortedSubscriptions = @()
$SortedSubscriptions += ($AllEnabledSubscriptions | Where-Object -FilterScript {$SelectedSubscriptionIDs -contains $_.Id} )			# User-selected
$SortedSubscriptions += ($AllEnabledSubscriptions | Where-Object -FilterScript {$SelectedSubscriptionIDs -notContains $_.Id} )		# Remaining entries
# $SortedSubscriptions += ($AllEnabledSubscriptions2 | Where-Object -FilterScript {$SelectedSubscriptionIDs -notContains $_.Id} )	# Remaining entries (with weird removed)


# +---------------------------------------------+
# |  if -List was specified...					|
# +---------------------------------------------+
if ($List)
{
	foreach ($sub in $subscriptions)
	{
		$x = select-AzSubscription -Subscription $sub.Id -Tenant $sub.TenantId
		# $x2 = Select-AzureSubscription -SubscriptionId $sub.id -ErrorAction SilentlyContinue

		# Retrieve the custom roles and then look through to build our structure
		$CustomRBACs = Get-AzRoleDefinition -custom
		foreach ($role in $CustomRBACs)
		{
			# If we don't already have the definition
		
			$Entry 				= New-Object -TypeName CustomRole
			$Entry.Name 		= $role.Name
			$Entry.Id 			= $role.Id
			$Entry.SubName		= $sub.Name
			$Entry.Description	= $role.Description.Trim()
			$Entry.Definition	= ""
			if ($role.Actions.Count -gt 0)			{ $Entry.Definition	+= "  ACTION         " + $($role.Actions -join        $($crlf + "  ACTION         ")) }
			if ($role.NotActions.Count -gt 0)		{ $Entry.Definition	+= "  NOTACTION      " + $($role.NotActions -join     $($crlf + "  NOTACTION      ")) }
			if ($role.DataActions.Count -gt 0)		{ $Entry.Definition	+= "  DATAACTION     " + $($role.DataActions -join    $($crlf + "  NODATAACTION   ")) }
			if ($role.NotDataActions.Count -gt 0)	{ $Entry.Definition	+= "  NOTDATAACTION  " + $($role.NotDataActions -join $($crlf + "  NOTDATAACTION  ")) }
			$Entry.Scopes		=  "  " + ($role.AssignableScopes -join "  $crlf")		# .Replace("/subscriptions/","")
			
			# Process Assigneees
			$Entry.Assignees = ""
			$Assignments = Get-AzRoleAssignment -RoleDefinitionId $role.Id
			foreach ($assignment in $Assignments)
			{
				$Entry.Assignees += "  " + $assignment.DisplayName + " - " + $assignment.SignInName + "  (" + $assignment.ObjectType + ")" + $crlf
			}
			$RoleDefinitions	+= $Entry
		}
	}
	
	# Now output the results
	write-host -ForegroundColor Yellow "See the popup for the custom RBAC Role Definitions"
	$RoleDefinitions | Out-Gridview -Title "Custom Azure RBAC Role Definitions"
	
	# Output a text version
	foreach ($role in $RoleDefinitions)
	{
		write-host -ForegroundColor Yellow -NoNewLine "`n`n$($role.Name)   "
		write-host "[$($role.Id)]"
		write-host -ForegroundColor Gray $role.Description.Trim()
		write-host "Found in: $($Entry.SubName)"
		write-host "---- ACTIONS ----`n$($role.Definition)"
		write-host "---- SCOPES ----`n$($role.Scopes)"
		write-host "---- ASSIGNEES ----`n$($role.Assignees)"
	}
	Return $null		# Exit
}




# +---------------------------------------------+
# |  DEFINE the custom RBAC roles 				|
# +---------------------------------------------+
#
# Cloud Automation
# Cloud Power User
# Cloud Auditor
# Cloud Key Vault Admin
# Cloud User Access Admin
# Cloud Network Admin
# Cloud Firewall Operator
# Cloud Security Admin
# Cloud Virtual Machine Operator
# Cloud Backup Admin
# Cloud Locks Admin
# Cloud Database Auditor
# Cloud Developer
# and more...
#

#
# First, make sure we're in an ENABLED subscriptions
#
Try
{
	$x = Get-AzRoleDefinition -Name "Reader" -ErrorAction Stop 
}
Catch
{
	# If we got an error, then prompt to choose a working subscription
	write-warning "Please choose a working subscription (see pop-up)"
	$s = (Get-AzSubscription) | Where-Object {$_.State -like "Enabled"} `
												| Sort-Object -Property Name `
												| Select-Object -Property Name, Id, TenantId, State `
												| Out-Gridview -Title "Please choose ONE working subscription:" -Passthru
	if ($s.count -eq 0) { return $null }
	$x = select-AzSubscription -Subscription $s[0].Id -Tenant $s[0].TenantId -ErrorAction Stop
}


# +-----------------------------+
# |  Cloud Automation			|
# +-----------------------------+
$AutomationUser	 = Create-NewRoleDefinition -Name "Cloud Automation" `
					-Description "Automation contributor for VSTS and other trusted automated deployments of most IaaS and PaaS services. [Restricted to Automation Use Only!]"

$AutomationUser.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$AutomationUser.Actions += "*"						# Allow Everything like contributor

# Disallow these actions
$AutomationUser.Notactions += "Microsoft.Authorization/*/delete"
$AutomationUser.Notactions += "Microsoft.Authorization/*/write"
$AutomationUser.Notactions += "Microsoft.Authorization/elevateAccess/Action"
$AutomationUser.NotActions += "Microsoft.Billing/*/write"									# do NOT allow billing access! Otherwise can create & rename subscriptions!
$AutomationUser.Notactions += "Microsoft.Security/*/write"
$AutomationUser.Notactions += "Microsoft.Security/*/delete"
$AutomationUser.Notactions += "Microsoft.Security/*/action"
$AutomationUser.Notactions += "Microsoft.ClassicCompute/*"
$AutomationUser.Notactions += "Microsoft.ClassicNetwork/*"
$AutomationUser.Notactions += "Microsoft.ClassicStorage/*"

$AutomationUser.Notactions += "Microsoft.Network/connections/delete"
$AutomationUser.Notactions += "Microsoft.Network/connections/sharedKey/*"
$AutomationUser.Notactions += "Microsoft.Network/connections/write"
$AutomationUser.Notactions += "Microsoft.Network/expressRouteCircuits/authorizations/*"
$AutomationUser.Notactions += "Microsoft.Network/expressRouteCircuits/delete"
$AutomationUser.Notactions += "Microsoft.Network/expressRouteCircuits/write"
$AutomationUser.Notactions += "Microsoft.Network/expressRouteCircuits/peerings/delete"
$AutomationUser.Notactions += "Microsoft.Network/expressRouteCircuits/peerings/write"
$AutomationUser.Notactions += "Microsoft.Network/routeFilters/delete"
$AutomationUser.Notactions += "Microsoft.Network/routeFilters/write"
$AutomationUser.Notactions += "Microsoft.Network/routeFilters/*/delete"
$AutomationUser.Notactions += "Microsoft.Network/routeFilters/*/write"
$AutomationUser.Notactions += "Microsoft.Network/routeTables/delete"
$AutomationUser.Notactions += "Microsoft.Network/routeTables/write"
$AutomationUser.Notactions += "Microsoft.Network/routeTables/*/delete"
$AutomationUser.Notactions += "Microsoft.Network/routeTables/*/write"
$AutomationUser.Notactions += "Microsoft.Network/virtualnetworkgateways/*/action"
$AutomationUser.Notactions += "Microsoft.Network/virtualnetworkgateways/delete"
$AutomationUser.Notactions += "Microsoft.Network/virtualNetworks/peer/action"
$AutomationUser.Notactions += "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write"
$AutomationUser.Notactions += "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete"
$AutomationUser.Notactions += "Microsoft.Network/unregister/action"

$AutomationUser.Notactions += "Microsoft.Support/*/write"					# Cannot create support tickets

$RoleDefinitions += $AutomationUser		# Add to array of custom roles as final step...


# +-----------------------------+
# |  Cloud Security Admin	|
# +-----------------------------+
$SecurityAdmin	 = Create-NewRoleDefinition -Name "Cloud Security Admin" `
					-Description "Security Administrator role"

$SecurityAdmin.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$SecurityAdmin.Actions += "*/read"							# Allow Read
$SecurityAdmin.Actions += "Microsoft.Authorization/*/read"
$SecurityAdmin.Actions += "Microsoft.Authorization/policyAssignments/*"
$SecurityAdmin.Actions += "Microsoft.Authorization/policyDefinitions/*"
$SecurityAdmin.Actions += "Microsoft.Authorization/policySetDefinitions/*"
$SecurityAdmin.Actions += "Microsoft.Insights/alertRules/*"
$SecurityAdmin.Actions += "Microsoft.Management/managementGroups/read"
$SecurityAdmin.Actions += "Microsoft.operationalInsights/workspaces/*/read"
$SecurityAdmin.Actions += "Microsoft.Resources/deployments/*"
$SecurityAdmin.Actions += "Microsoft.Resources/subscriptions/resourceGroups/read"
$SecurityAdmin.Actions += "Microsoft.Security/*"
$SecurityAdmin.Actions += "Microsoft.Support/*"

$RoleDefinitions += $SecurityAdmin		# Add to array of custom roles as final step...


# +-----------------------------+
# |  Cloud Troubleshooter	|
# +-----------------------------+
$Troubleshooter = Create-NewRoleDefinition -Name "Cloud Troubleshooter" `
					-Description "ACan view logs, configurations, and create VM and storage snapshots for troubleshooting."

$Troubleshooter.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$Troubleshooter.Actions += "*/read"
$Troubleshooter.Actions += "Microsoft.Insights/*"
$Troubleshooter.Actions += "Microsoft.ApiManagement/service/tenant/save/action"		# Creates commit with configuration snapshot
$Troubleshooter.Actions += "Microsoft.ApiManagement/service/tenant/validate/action"	# Validates changes from the specified branch
$Troubleshooter.Actions += "Microsoft.Compute/snapshots/write"
$Troubleshooter.Actions += "Microsoft.Compute/snapshots/delete"
$Troubleshooter.Actions += "Microsoft.Compute/snapshots/beginGetAccess/action"
$Troubleshooter.Actions += "Microsoft.Compute/snapshots/endGetAccess/action"
$Troubleshooter.Actions += "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/write"
$Troubleshooter.Actions += "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/delete"
$Troubleshooter.Actions += "microsoft.web/sites/restoresnapshot/action"
$Troubleshooter.Actions += "microsoft.web/sites/restorefromdeletedapp/action"
$Troubleshooter.Actions += "microsoft.web/sites/slots/restoresnapshot/action"
$Troubleshooter.Actions += "microsoft.web/sites/triggeredwebjobs/delete"
$Troubleshooter.Actions += "microsoft.web/sites/triggeredwebjobs/run/action"

$RoleDefinitions += $Troubleshooter		# Add to array of custom roles as final step...


# +-----------------------------+
# |  Cloud Database Admin		|
# +-----------------------------+
$DBadmin = Create-NewRoleDefinition -Name "Cloud Database Admin" `
					-Description "Allows administration of most data and database PaaS services."

$DBadmin.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$DBadmin.Actions += "*/read"
$DBadmin.Actions += "Microsoft.AzureData/*"
$DBadmin.Actions += "Microsoft.Billing/*/read"				# do NOT allow full billing access! Otherwise can create & rename subscriptions!
$DBadmin.Actions += "Microsoft.Cache/*"
$DBadmin.Actions += "Microsoft.Databricks/*"
$DBadmin.Actions += "Microsoft.DataCatalog/*"
$DBadmin.Actions += "Microsoft.DataFactory/*"
$DBadmin.Actions += "Microsoft.DataLakeAnalytics/*"
$DBadmin.Actions += "Microsoft.DataLakeStore/*"
$DBadmin.Actions += "Microsoft.DBforMySQL/*"
$DBadmin.Actions += "Microsoft.DBforPostgreSQL/*"
$DBadmin.Actions += "Microsoft.DocumentDB/*"
$DBadmin.Actions += "Microsoft.Sql/*"
# $DBadmin.Actions += "Microsoft.SqlVirtualMachine/*"  # Not yet available
$DBadmin.Actions += "Microsoft.OperationalInsights/workspaces/query/DatabricksAccounts/*"
# $DBadmin.Actions += "Cloudyn.Analytics/*/read"
$DBadmin.Actions += "Microsoft.Support/*"

# Disallow these actions
$DBadmin.NotActions += "Microsoft.Cache/redis/firewallRules/delete"
$DBadmin.NotActions += "Microsoft.Cache/redis/firewallRules/write"
$DBadmin.Notactions += "Microsoft.DataLakeStore/accounts/firewallRules/delete"
$DBadmin.Notactions += "Microsoft.DataLakeStore/accounts/firewallRules/write"
$DBadmin.Notactions += "Microsoft.DBforPostgreSQL/servers/firewallRules/write"
$DBadmin.Notactions += "Microsoft.DBforPostgreSQL/servers/firewallRules/delete"
$DBadmin.Notactions += "Microsoft.Sql/servers/firewallRules/delete"
$DBadmin.Notactions += "Microsoft.Sql/servers/firewallRules/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/auditingSettings/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/auditingPolicies/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/databases/auditingPolicies/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/databases/auditingSettings/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/securityAlertPolicies/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/virtualNetworkRules/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/virtualNetworkRules/delete"
$DBadmin.Notactions += "Microsoft.Sql/servers/communicationLinks/write"
$DBadmin.Notactions += "Microsoft.Sql/servers/communicationLinks/delete"

$RoleDefinitions += $DBadmin		# Add to array of custom roles as final step...



# +-----------------------------+
# |  Cloud Developer			|
# +-----------------------------+
$Developer = Create-NewRoleDefinition -Name "Cloud Developer" `
					-Description "Allows most IaaS and PaaS services, excluding most network provisioning"

$Developer.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$Developer.Actions += "*/read"
$Developer.Actions += "Microsoft.ADHybridHealthService/*"
$Developer.Actions += "Microsoft.Advisor/*"
$Developer.Actions += "Microsoft.AnalysisServices/*"
$Developer.Actions += "Microsoft.ApiManagement/*"
$Developer.Actions += "Microsoft.Automation/*"
$Developer.Actions += "Microsoft.Batch/*"
$Developer.Actions += "Microsoft.Billing/*/read"				# do NOT allow full billing access! Otherwise can create & rename subscriptions!
$Developer.Actions += "Microsoft.BingMaps/*"
$Developer.Actions += "Microsoft.Cache/*"
$Developer.Actions += "Microsoft.CognitiveServices/*"
$Developer.Actions += "Microsoft.Commerce/*"
$Developer.Actions += "Microsoft.Compute/*"
$Developer.Actions += "Microsoft.ContainerInstance/*"
$Developer.Actions += "Microsoft.ContainerRegistry/*"
$Developer.Actions += "Microsoft.ContainerRegistry/registries/pull/read"	# Supposedly needs to be specifically listed...
$Developer.Actions += "Microsoft.ContainerRegistry/registries/push/write"	# Supposedly needs to be specifically listed...
$Developer.Actions += "Microsoft.ContainerService/*"
# $Developer.Actions += "Microsoft.ContentModerator/*"		# Deprecated
# $Developer.Actions += "Microsoft.CustomerInsights/*"
$Developer.Actions += "Microsoft.DataBricks/*"
$Developer.Actions += "Microsoft.DataCatalog/*"
$Developer.Actions += "Microsoft.DataFactory/*"
$Developer.Actions += "Microsoft.DataLakeAnalytics/*"
$Developer.Actions += "Microsoft.DataLakeStore/*"
$Developer.Actions += "Microsoft.DBforMySQL/*"
$Developer.Actions += "Microsoft.DBforPostgreSQL/*"
$Developer.Actions += "Microsoft.Devices/*"
$Developer.Actions += "Microsoft.DevTestLab/*"
$Developer.Actions += "Microsoft.DocumentDB/*"
$Developer.Actions += "Microsoft.DeploymentManager/*"
$Developer.Actions += "Microsoft.DomainRegistration/*"
# $Developer.Actions += "Microsoft.DynamicsLcs/*"
$Developer.Actions += "Microsoft.EventHub/*"
$Developer.Actions += "Microsoft.Features/*"
$Developer.Actions += "Microsoft.HDInsight/*"
$Developer.Actions += "Microsoft.ImportExport/*"
$Developer.Actions += "Microsoft.Insights/*"
$Developer.Actions += "Microsoft.KeyVault/*"
$Developer.Actions += "Microsoft.Logic/*"
$Developer.Actions += "Microsoft.MachineLearning/*"
$Developer.Actions += "Microsoft.MarketplaceOrdering/*"
$Developer.Actions += "Microsoft.Media/*"
$Developer.Actions += "Microsoft.Network/virtualNetworks/subnets/join/action"
$Developer.Actions += "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action"
$Developer.Actions += "Microsoft.NotificationHubs/*"
$Developer.Actions += "Microsoft.OperationalInsights/*"
$Developer.Actions += "Microsoft.OperationsManagement/*"
$Developer.Actions += "Microsoft.PowerBIDedicated/*"
$Developer.Actions += "Microsoft.RecoveryServices/*"
$Developer.Actions += "Microsoft.Relay/*"
$Developer.Actions += "Microsoft.Resourcehealth/*"
$Developer.Actions += "Microsoft.Resources/*"
$Developer.Actions += "Microsoft.Scheduler/*"
$Developer.Actions += "Microsoft.Search/*"
$Developer.Actions += "Microsoft.ServiceBus/*"
$Developer.Actions += "Microsoft.ServiceFabric/*"
$Developer.Actions += "Microsoft.Sql/*"
# $Developer.Actions += "Microsoft.SqlVirtualMachine/*"  # Not yet available
$Developer.Actions += "Microsoft.Storage/*"
$Developer.Actions += "Microsoft.StreamAnalytics/*"
$Developer.Actions += "Microsoft.Support/*"
$Developer.Actions += "microsoft.web/*"
# $Developer.Actions += "AppDynamics.APM/*"
# $Developer.Actions += "Cloudyn.Analytics/*/read"

# Tags
$Developer.Actions += "Microsoft.Resources/tags/*"
$Developer.Actions += "Microsoft.Resources/subscriptions/tagNames/*"

# Disallow these actions
$Developer.Notactions += "Microsoft.Authorization/*/delete"
$Developer.Notactions += "Microsoft.Authorization/*/write"
$Developer.Notactions += "Microsoft.Authorization/elevateAccess/Action"
$Developer.Notactions += "Microsoft.Compute/disks/beginGetAccess/action"					# Allows export of managed disk
$Developer.Notactions += "Microsoft.Storage/storageAccounts/listAccountSas/action"			# Disable listing of SAS keys
$Developer.Notactions += "Microsoft.Storage/storageAccounts/listServiceSas/action"
$Developer.Notactions += "Microsoft.Security/*/write"
$Developer.Notactions += "Microsoft.Security/*/delete"
$Developer.Notactions += "Microsoft.Security/*/action"
$Developer.Notactions += "Microsoft.StorSimple/*/write"
$Developer.Notactions += "Microsoft.StorSimple/*/delete"

$RoleDefinitions += $Developer		# Add to array of custom roles as final step...

# +---------------------------------+
# |  Cloud Pipeline Developer		|
# +---------------------------------+
$PipeDeveloper = Create-NewRoleDefinition -Name "Cloud Pipeline Developer" `
					-Description "Enables building of deployment pipelines. Can build and delete most things."

$PipeDeveloper.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$PipeDeveloper.Actions += "*/read"
$PipeDeveloper.Actions += "Microsoft.DeploymentManager/*"
$PipeDeveloper.Actions += "Microsoft.ADHybridHealthService/*"
$PipeDeveloper.Actions += "Microsoft.Advisor/*"
$PipeDeveloper.Actions += "Microsoft.AnalysisServices/*"
$PipeDeveloper.Actions += "Microsoft.ApiManagement/*"
$PipeDeveloper.Actions += "Microsoft.Automation/*"
$PipeDeveloper.Actions += "Microsoft.Batch/*"
$PipeDeveloper.Actions += "Microsoft.Billing/*/read"				# do NOT allow full billing access! Otherwise can create & rename subscriptions!
$PipeDeveloper.Actions += "Microsoft.BingMaps/*"
$PipeDeveloper.Actions += "Microsoft.Cache/*"
$PipeDeveloper.Actions += "Microsoft.CognitiveServices/*"
$PipeDeveloper.Actions += "Microsoft.Commerce/*"
$PipeDeveloper.Actions += "Microsoft.Compute/*"
$PipeDeveloper.Actions += "Microsoft.ContainerInstance/*"
$PipeDeveloper.Actions += "Microsoft.ContainerRegistry/*"
$PipeDeveloper.Actions += "Microsoft.ContainerRegistry/registries/pull/read"	# Supposedly needs to be specifically listed...
$PipeDeveloper.Actions += "Microsoft.ContainerRegistry/registries/push/write"	# Supposedly needs to be specifically listed...
$PipeDeveloper.Actions += "Microsoft.ContainerService/*"
# $PipeDeveloper.Actions += "Microsoft.ContentModerator/*"		# Deprecated
# $PipeDeveloper.Actions += "Microsoft.CustomerInsights/*"
$PipeDeveloper.Actions += "Microsoft.DataBricks/*"
$PipeDeveloper.Actions += "Microsoft.DataCatalog/*"
$PipeDeveloper.Actions += "Microsoft.DataFactory/*"
$PipeDeveloper.Actions += "Microsoft.DataLakeAnalytics/*"
$PipeDeveloper.Actions += "Microsoft.DataLakeStore/*"
$PipeDeveloper.Actions += "Microsoft.DBforMySQL/*"
$PipeDeveloper.Actions += "Microsoft.DBforPostgreSQL/*"
$PipeDeveloper.Actions += "Microsoft.Devices/*"
$PipeDeveloper.Actions += "Microsoft.DevTestLab/*"
$PipeDeveloper.Actions += "Microsoft.DocumentDB/*"
$PipeDeveloper.Actions += "Microsoft.DomainRegistration/*"
$PipeDeveloper.Actions += "Microsoft.EventHub/*"
$PipeDeveloper.Actions += "Microsoft.Features/*"
$PipeDeveloper.Actions += "Microsoft.HDInsight/*"
$PipeDeveloper.Actions += "Microsoft.ImportExport/*"
$PipeDeveloper.Actions += "Microsoft.Insights/*"
$PipeDeveloper.Actions += "Microsoft.KeyVault/*"
$PipeDeveloper.Actions += "Microsoft.Logic/*"
$PipeDeveloper.Actions += "Microsoft.MachineLearning/*"
$PipeDeveloper.Actions += "Microsoft.MarketplaceOrdering/*"
$PipeDeveloper.Actions += "Microsoft.Media/*"
$PipeDeveloper.Actions += "Microsoft.Network/virtualNetworks/subnets/join/action"
$PipeDeveloper.Actions += "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action"
$PipeDeveloper.Actions += "Microsoft.NotificationHubs/*"
$PipeDeveloper.Actions += "Microsoft.OperationalInsights/*"
$PipeDeveloper.Actions += "Microsoft.OperationsManagement/*"
$PipeDeveloper.Actions += "Microsoft.PowerBIDedicated/*"
$PipeDeveloper.Actions += "Microsoft.RecoveryServices/*"
$PipeDeveloper.Actions += "Microsoft.Relay/*"
$PipeDeveloper.Actions += "Microsoft.Resourcehealth/*"
$PipeDeveloper.Actions += "Microsoft.Resources/*"
$PipeDeveloper.Actions += "Microsoft.Scheduler/*"
$PipeDeveloper.Actions += "Microsoft.Search/*"
$PipeDeveloper.Actions += "Microsoft.ServiceBus/*"
$PipeDeveloper.Actions += "Microsoft.ServiceFabric/*"
$PipeDeveloper.Actions += "Microsoft.Sql/*"
# $PipeDeveloper.Actions += "Microsoft.SqlVirtualMachine/*"  # Not yet available
$PipeDeveloper.Actions += "Microsoft.Storage/*"
$PipeDeveloper.Actions += "Microsoft.StreamAnalytics/*"
$PipeDeveloper.Actions += "Microsoft.Support/*"
$PipeDeveloper.Actions += "microsoft.web/*"
# $PipeDeveloper.Actions += "AppDynamics.APM/*"
# $PipeDeveloper.Actions += "Cloudyn.Analytics/*/read"

# Tags
$PipeDeveloper.Actions += "Microsoft.Resources/tags/*"
$PipeDeveloper.Actions += "Microsoft.Resources/subscriptions/tagNames/*"

# Disallow these actions
$PipeDeveloper.Notactions += "Microsoft.Authorization/*/delete"
$PipeDeveloper.Notactions += "Microsoft.Authorization/*/write"
$PipeDeveloper.Notactions += "Microsoft.Authorization/elevateAccess/Action"
$PipeDeveloper.Notactions += "Microsoft.Compute/disks/beginGetAccess/action"					# Allows export of managed disk
$PipeDeveloper.Notactions += "Microsoft.Storage/storageAccounts/listAccountSas/action"			# Disable listing of SAS keys
$PipeDeveloper.Notactions += "Microsoft.Storage/storageAccounts/listServiceSas/action"
$PipeDeveloper.Notactions += "Microsoft.Security/*/write"
$PipeDeveloper.Notactions += "Microsoft.Security/*/delete"
$PipeDeveloper.Notactions += "Microsoft.Security/*/action"
$PipeDeveloper.Notactions += "Microsoft.StorSimple/*/write"
$PipeDeveloper.Notactions += "Microsoft.StorSimple/*/delete"

$RoleDefinitions += $PipeDeveloper		# Add to array of custom roles as final step...


# +---------------------------------+
# |  Cloud Full Stack Developer	|
# +---------------------------------+
$FSDeveloper = Create-NewRoleDefinition -Name "Cloud Full Stack Developer" `
					-Description "Allows most IaaS and PaaS services, including most networking except User-Defined Routes and VM Public-IP address deployments"

$FSDeveloper.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$FSDeveloper.Actions += "*/read"
$FSDeveloper.Actions += "Microsoft.ADHybridHealthService/*"
$FSDeveloper.Actions += "Microsoft.Advisor/*"
$FSDeveloper.Actions += "Microsoft.AnalysisServices/*"
$FSDeveloper.Actions += "Microsoft.ApiManagement/*"
$FSDeveloper.Actions += "Microsoft.Automation/*"
$FSDeveloper.Actions += "Microsoft.Batch/*"
$FSDeveloper.Actions += "Microsoft.Billing/*/read"				# do NOT allow full billing access! Otherwise can create & rename subscriptions!
$FSDeveloper.Actions += "Microsoft.BingMaps/*"
$FSDeveloper.Actions += "Microsoft.Cache/*"
$FSDeveloper.Actions += "Microsoft.CognitiveServices/*"
$FSDeveloper.Actions += "Microsoft.Commerce/*"
$FSDeveloper.Actions += "Microsoft.Compute/*"
$FSDeveloper.Actions += "Microsoft.ContainerInstance/*"
$FSDeveloper.Actions += "Microsoft.ContainerRegistry/*"
$FSDeveloper.Actions += "Microsoft.ContainerService/*"
# $FSDeveloper.Actions += "Microsoft.ContentModerator/*"			# Deprecated
$FSDeveloper.Actions += "Microsoft.CustomerInsights/*"
$FSDeveloper.Actions += "Microsoft.DataCatalog/*"
$FSDeveloper.Actions += "Microsoft.DataFactory/*"
$FSDeveloper.Actions += "Microsoft.DataLakeAnalytics/*"
$FSDeveloper.Actions += "Microsoft.DataLakeStore/*"
$FSDeveloper.Actions += "Microsoft.DBforMySQL/*"
$FSDeveloper.Actions += "Microsoft.DBforPostgreSQL/*"
$FSDeveloper.Actions += "Microsoft.Devices/*"
$FSDeveloper.Actions += "Microsoft.DevTestLab/*"
$FSDeveloper.Actions += "Microsoft.DocumentDB/*"
$FSDeveloper.Actions += "Microsoft.DomainRegistration/*"
# $FSDeveloper.Actions += "Microsoft.DynamicsLcs/*"
$FSDeveloper.Actions += "Microsoft.EventHub/*"
$FSDeveloper.Actions += "Microsoft.Features/*"
$FSDeveloper.Actions += "Microsoft.HDInsight/*"
$FSDeveloper.Actions += "Microsoft.ImportExport/*"
$FSDeveloper.Actions += "Microsoft.Insights/*"
$FSDeveloper.Actions += "Microsoft.KeyVault/*"
$FSDeveloper.Actions += "Microsoft.Logic/*"
$FSDeveloper.Actions += "Microsoft.MachineLearning/*"
$FSDeveloper.Actions += "Microsoft.MarketplaceOrdering/*"
$FSDeveloper.Actions += "Microsoft.Media/*"
$FSDeveloper.Actions += "Microsoft.Network/*"
$FSDeveloper.Actions += "Microsoft.NotificationHubs/*"
$FSDeveloper.Actions += "Microsoft.OperationalInsights/*"
$FSDeveloper.Actions += "Microsoft.OperationsManagement/*"
$FSDeveloper.Actions += "Microsoft.PowerBIDedicated/*"
$FSDeveloper.Actions += "Microsoft.RecoveryServices/*"
$FSDeveloper.Actions += "Microsoft.Relay/*"
$FSDeveloper.Actions += "Microsoft.Resourcehealth/*"
$FSDeveloper.Actions += "Microsoft.Resources/*"
$FSDeveloper.Actions += "Microsoft.Scheduler/*"
$FSDeveloper.Actions += "Microsoft.Search/*"
$FSDeveloper.Actions += "Microsoft.ServiceBus/*"
$FSDeveloper.Actions += "Microsoft.ServiceFabric/*"
$FSDeveloper.Actions += "Microsoft.Sql/*"
$FSDeveloper.Actions += "Microsoft.Storage/*"
$FSDeveloper.Actions += "Microsoft.StreamAnalytics/*"
$FSDeveloper.Actions += "Microsoft.Support/*"
$FSDeveloper.Actions += "microsoft.web/*"
# $FSDeveloper.Actions += "AppDynamics.APM/*"
# $FSDeveloper.Actions += "Cloudyn.Analytics/*/read"

# Disallow these actions
$FSDeveloper.Notactions += "Microsoft.Authorization/*/delete"
$FSDeveloper.Notactions += "Microsoft.Authorization/*/write"
$FSDeveloper.Notactions += "Microsoft.Authorization/elevateAccess/Action"
$FSDeveloper.Notactions += "Microsoft.Compute/disks/beginGetAccess/action"					# Allows export of managed disk
$FSDeveloper.Notactions += "Microsoft.Storage/storageAccounts/listAccountSas/action"			# Disable listing of SAS keys
$FSDeveloper.Notactions += "Microsoft.Storage/storageAccounts/listServiceSas/action"

$FSDeveloper.Notactions += "Microsoft.Security/*/write"
$FSDeveloper.Notactions += "Microsoft.Security/*/delete"
$FSDeveloper.Notactions += "Microsoft.Security/*/action"
$FSDeveloper.Notactions += "Microsoft.StorSimple/*/write"
$FSDeveloper.Notactions += "Microsoft.StorSimple/*/delete"
$FSDeveloper.Notactions += "Microsoft.ClassicCompute/*"
$FSDeveloper.Notactions += "Microsoft.ClassicNetwork/*"
$FSDeveloper.Notactions += "Microsoft.ClassicStorage/*"

$FSDeveloper.Notactions += "Microsoft.Network/connections/delete"
$FSDeveloper.Notactions += "Microsoft.Network/connections/sharedKey/*"
$FSDeveloper.Notactions += "Microsoft.Network/connections/write"
$FSDeveloper.Notactions += "Microsoft.Network/dnszones/write"
$FSDeveloper.Notactions += "Microsoft.Network/dnszones/delete"
$FSDeveloper.Notactions += "Microsoft.Network/dnszones/*/write"
$FSDeveloper.Notactions += "Microsoft.Network/dnszones/*/delete"
$FSDeveloper.Notactions += "Microsoft.Network/expressRouteCircuits/*"
$FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/delete"
$FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/join/action"
# $FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/loadBalancerPools/delete"
# $FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/loadBalancerPools/join/action"
# $FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/loadBalancerPools/read"
# $FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/loadBalancerPools/write"
$FSDeveloper.Notactions += "Microsoft.Network/publicIPAddresses/write"
$FSDeveloper.Notactions += "Microsoft.Network/routeFilters/delete"
$FSDeveloper.Notactions += "Microsoft.Network/routeFilters/write"
$FSDeveloper.Notactions += "Microsoft.Network/routeFilters/*/delete"
$FSDeveloper.Notactions += "Microsoft.Network/routeFilters/*/write"
$FSDeveloper.Notactions += "Microsoft.Network/routeTables/delete"
$FSDeveloper.Notactions += "Microsoft.Network/routeTables/write"
$FSDeveloper.Notactions += "Microsoft.Network/routeTables/*/delete"
$FSDeveloper.Notactions += "Microsoft.Network/routeTables/*/write"
$FSDeveloper.Notactions += "Microsoft.Network/virtualnetworkgateways/*/action"
$FSDeveloper.Notactions += "Microsoft.Network/virtualnetworkgateways/delete"
$FSDeveloper.Notactions += "Microsoft.Network/virtualNetworks/peer/action"
$FSDeveloper.Notactions += "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete"
$FSDeveloper.Notactions += "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write"
$FSDeveloper.Notactions += "Microsoft.Network/trafficManagerProfiles/azureEndpoints/write"
$FSDeveloper.Notactions += "Microsoft.Network/trafficManagerProfiles/azureEndpoints/delete"
# $FSDeveloper.Notactions += "Microsoft.Network/trafficManagerProfiles/azureEndpoints/*/write"
# $FSDeveloper.Notactions += "Microsoft.Network/trafficManagerProfiles/azureEndpoints/*/delete"
$FSDeveloper.Notactions += "Microsoft.Network/unregister/action"

$RoleDefinitions += $FSDeveloper		# Add to array of custom roles as final step...


# +-----------------------------+
# |  Cloud Auditor				|
# +-----------------------------+
$Auditor = Create-NewRoleDefinition -Name "Cloud Auditor" `
					-Description "Allows reading of everything (including limited storage account access), full access to Microsoft Insights, but excludes content and secrets"

$Auditor.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$Auditor.Actions += "*/read"
# $Auditor.Actions += "Cloudyn.Analytics/*/read"
$Auditor.Actions += "Microsoft.Insights/*"
$Auditor.Actions += "Microsoft.Compute/virtualMachines/extensions/*"		# Allow configuring of OMS
$Auditor.Actions += "Microsoft.Storage/storageAccounts/listkeys/action"
$Auditor.Actions += "Microsoft.ClassicStorage/storageAccounts/listKeys/action"
$Auditor.Actions += "Microsoft.KeyVault/vaults/accessPolicies/write"		# Allows provisioning of self-access for monitoring expiry
$Auditor.Actions += "Microsoft.KeyVault/vaults/write"						# Required with /accessPolicies/write due to a BUG
$Auditor.Actions += "Microsoft.KeyVault/vaults/eventGridFilters/*"
$Auditor.Actions += "Microsoft.Resources/tags/*"

$Auditor.NotDataActions += "Microsoft.Storage/storageAccounts/*/write"
$Auditor.NotDataActions += "Microsoft.Storage/storageAccounts/*/delete"
$Auditor.NotDataActions += "Microsoft.Storage/storageAccounts/*/action"
# $Auditor.NotDataActions += "Microsoft.Storage/storageAccounts/*/read"		# may need this for $log container

$RoleDefinitions += $Auditor		# Add to array of custom roles as final step..


# +-----------------------------+
# |  Cloud Key Vault Admin		|
# +-----------------------------+
$KeyVaultAdmin = Create-NewRoleDefinition -Name "Cloud Key Vault Admin" `
					-Description 'Allows management of Key Vaults (including the secrets within), storage account keys, and most other keys.'

$KeyVaultAdmin.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$KeyVaultAdmin.Actions += "*/read"
$KeyVaultAdmin.Actions += "Microsoft.KeyVault/*"
$KeyVaultAdmin.Actions += "Microsoft.Security/*/read"
$KeyVaultAdmin.Actions += "Microsoft.Compute/disks/beginGetAccess/action"
$KeyVaultAdmin.Actions += "Microsoft.Storage/storageAccounts/listAccountSas/action"
$KeyVaultAdmin.Actions += "Microsoft.Storage/storageAccounts/listServiceSas/action"
$KeyVaultAdmin.Actions += "Microsoft.ClassicStorage/storageAccounts/listKeys/action"
$KeyVaultAdmin.Actions += "Microsoft.ClassicStorage/storageAccounts/regenerateKey/action"
$KeyVaultAdmin.Actions += "Microsoft.ImportExport/jobs/listBitLockerKeys/action"

# Allow these actions as well across a variety of providers
$KeyVaultAdmin.Actions += "*/enableKeyVault/action"
$KeyVaultAdmin.Actions += "*/keys/read"
$KeyVaultAdmin.Actions += "*/listKeys/read"
$KeyVaultAdmin.Actions += "*/listKeys/action"
$KeyVaultAdmin.Actions += "*/listKeyVaultKeys/action"
$KeyVaultAdmin.Actions += "*/regenerateKey/action"
$KeyVaultAdmin.Actions += "*/regenerateKeys/action"
$KeyVaultAdmin.Actions += "*/regenerateAccessKey/action"
$KeyVaultAdmin.Actions += "*/regenerateauthkey/action"
$KeyVaultAdmin.Actions += "*/regeneratePrimaryKey/action"
$KeyVaultAdmin.Actions += "*/regenerateSecondaryKey/action"
$KeyVaultAdmin.Actions += "*/listauthkeys/action"
$KeyVaultAdmin.Actions += "*/listauthkeys/read"
$KeyVaultAdmin.Actions += "*/readonlykeys/action"
$KeyVaultAdmin.Actions += "*/readonlykeys/read"
$KeyVaultAdmin.Actions += "*/syncAutoStorageKeys/action"

# And allow a few miscellaneous
$KeyVaultAdmin.Actions += "Microsoft.OperationalInsights/workspaces/search/action"
$KeyVaultAdmin.Actions += "Microsoft.Resources/*/read"
$KeyVaultAdmin.Actions += "Microsoft.Resources/deployments/*"
$KeyVaultAdmin.Actions += "Microsoft.Support/*"

$RoleDefinitions += $KeyVaultAdmin		# Add to array of custom roles as final step..


# +-----------------------------+
# |  Cloud Firewall Operator	|
# +-----------------------------+
$FirewallOperator = Create-NewRoleDefinition -Name "Cloud Firewall Operator" `
					-Description "Allows configuring of Network Security Groups, WAF, and PaaS Firewalls"

$FirewallOperator.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$FirewallOperator.Actions += "*/read"
$FirewallOperator.Actions += "Microsoft.Resources/*"
$FirewallOperator.Actions += "Microsoft.Resources/deployments/*"
$FirewallOperator.Actions += "Microsoft.Authorization/*/read"
$FirewallOperator.Actions += "Microsoft.Insights/alertRules/*"
$FirewallOperator.Actions += "Microsoft.Network/azurefirewalls/*"
$FirewallOperator.Actions += "Microsoft.Network/networkSecurityGroups/*"

# Classic NSGs
$FirewallOperator.Actions += "Microsoft.ClassicNetwork/networkSecurityGroups/*"
$FirewallOperator.Actions += "Microsoft.ClassicNetwork/virtualNetworks/subnets/associatedNetworkSecurityGroups/*"

# Add in PaaS Firewall operator Actions
$FirewallOperator.Actions += "Microsoft.Cache/redis/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DataLakeAnalytics/accounts/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DataLakeStore/accounts/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DBforMariaDB/servers/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DBforMySQL/servers/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DBforPostgreSQL/servers/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.DBforPostgreSQL/serversv2/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.Sql/servers/firewallRules/*"
$FirewallOperator.Actions += "Microsoft.Security/webApplicationFirewalls/*"

# Add in PaaS Storage Account Actions
$FirewallOperator.Actions += "Microsoft.Storage/locations/deleteVirtualNetworkOrSubnets/*"
$FirewallOperator.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnectionProxies/*"
$FirewallOperator.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnections/*"
$FirewallOperator.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnectionsApproval/*"
$FirewallOperator.Actions += "Microsoft.Storage/storageAccounts/write"			# Needed to create/modify storage account firewall

$FirewallOperator.Actions += "Microsoft.Support/*"

$RoleDefinitions += $FirewallOperator		# Add to array of custom roles as final step..


# +-----------------------------+
# |  Cloud Network Admin		|
# +-----------------------------+
$NetworkAdmin = Create-NewRoleDefinition -Name "Cloud Network Admin" `
					-Description "Allows configuring of Network resources including NSGs and PaaS firewalls"

$NetworkAdmin.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$NetworkAdmin.Actions += "*/read"
$NetworkAdmin.Actions += "Microsoft.Resources/*"
$NetworkAdmin.Actions += "Microsoft.Resources/subscriptions/resourceGroups/*"		# Resource Group Contributor
$NetworkAdmin.Actions += "Microsoft.DomainRegistration/*"
$NetworkAdmin.Actions += "Microsoft.ClassicCompute/domainNames/*"
$NetworkAdmin.Actions += "Microsoft.ClassicCompute/virtualMachines/networkinterfaces/*"
$NetworkAdmin.Actions += "Microsoft.ClassicCompute/virtualMachines/associatedNetworkSecurityGroups/*"
$NetworkAdmin.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/networkInterfaces/*"
$NetworkAdmin.Actions += "Microsoft.ContainerInstance/locations/deleteVirtualNetworkOrSubnets/action"
$NetworkAdmin.Actions += "Microsoft.ContainerRegistry/locations/deleteVirtualNetworkOrSubnets/action"
$NetworkAdmin.Actions += "Microsoft.ClassicNetwork/*"
$NetworkAdmin.Actions += "Microsoft.Network/*"
$NetworkAdmin.Actions += "Microsoft.Insights/alertRules/*"
$NetworkAdmin.Actions += "Microsoft.Resources/deployments/*"
$NetworkAdmin.Actions += "Microsoft.ResourceHealth/availabilityStatuses/read"
$NetworkAdmin.Actions += "Microsoft.Resources/subscriptions/resourceGroups/read"
$NetworkAdmin.Actions += "Microsoft.DevTestLab/labs/virtualNetworks/*"
$NetworkAdmin.Actions += "Microsoft.insights/diagnosticSettings/write"	# Needed so T&N can provision for NSGs
$NetworkAdmin.Actions += "Microsoft.Support/*"

# Special Access to storage accounts (mostly for accessing diagnostics)
# Better approach is to grant Contributor to those storage accounts owned by Networking Team... Or create a resource Group therein.
# $NetworkAdmin.Actions += "Microsoft.Storage/storageAccounts/listkeys/action"

# Allow setting of Tags on certain resources
# (As there is no "Tags Administrator" role, write access to each resource must be granted
#  https://feedback.azure.com/forums/281804-azure-resource-manager/suggestions/38339788-create-a-tag-administrator-role
$NetworkAdmin.Actions += "Microsoft.Resources/tags/*"
$NetworkAdmin.Actions += "Microsoft.Resources/subscriptions/tagNames/*"
$NetworkAdmin.Actions += "Microsoft.Compute/virtualMachines/write"			# needed to configure tags
# $NetworkAdmin.Actions += "Microsoft.Compute/disks/write"


# Add in PaaS Firewall operator Actions
$NetworkAdmin.Actions += "Microsoft.Cache/redis/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DataLakeAnalytics/accounts/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DataLakeStore/accounts/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforMariaDB/servers/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforMySQL/servers/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforPostgreSQL/servers/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforPostgreSQL/serversv2/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.Sql/servers/firewallRules/*"
$NetworkAdmin.Actions += "Microsoft.Security/webApplicationFirewalls/*"

# Add in PaaS Virtual Network Actions
$NetworkAdmin.Actions += "Microsoft.DataLakeAnalytics/accounts/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.DataLakeStore/accounts/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforMariaDB/servers/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.DBforMySQL/servers/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.Sql/servers/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.DocumentDB/locations/deleteVirtualNetworkOrSubnets/*"
$NetworkAdmin.Actions += "Microsoft.DBforPostgreSQL/servers/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.EventHub/namespaces/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.EventHub/locations/deleteVirtualNetworkOrSubnets/action"
$NetworkAdmin.Actions += "Microsoft.EventHub/namespaces/networkrulesets/*"
$NetworkAdmin.Actions += "Microsoft.KeyVault/locations/deleteVirtualNetworkOrSubnets/action"
$NetworkAdmin.Actions += "Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings/*"
$NetworkAdmin.Actions += "Microsoft.ServiceBus/namespaces/virtualNetworkRules/*"
$NetworkAdmin.Actions += "Microsoft.ServiceBus/namespaces/networkrulesets/*"
$NetworkAdmin.Actions += "Microsoft.StorSimple/managers/devices/networkSettings/*"
$NetworkAdmin.Actions += "Microsoft.ServiceBus/locations/deleteVirtualNetworkOrSubnets/action"

# Add in PaaS Storage Account Actions
$NetworkAdmin.Actions += "Microsoft.Storage/locations/deleteVirtualNetworkOrSubnets/*"
$NetworkAdmin.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnectionProxies/*"
$NetworkAdmin.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnections/*"
$NetworkAdmin.Actions += "Microsoft.Storage/storageAccounts/privateEndpointConnectionsApproval/*"
$NetworkAdmin.Actions += "Microsoft.Storage/storageAccounts/write"			# Needed to create/modify storage account firewall

# Just-in-Time Access
$NetworkAdmin.Actions += "Microsoft.Security/locations/jitNetworkAccessPolicies/*"

# Other Network-related...
$NetworkAdmin.Actions += "Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action"
$NetworkAdmin.Actions += "Microsoft.Security/adaptiveNetworkHardenings/*"

# Special requirements for App Service Environments (ASE)
$NetworkAdmin.Actions += "Microsoft.Web/hostingEnvironments/Write"
$NetworkAdmin.Actions += "Microsoft.Web/hostingEnvironments/Join/Action"
$NetworkAdmin.Actions += "Microsoft.Web/hostingEnvironments/PrivateEndpointConnectionsApproval/Action"
$NetworkAdmin.Actions += "microsoft.web/locations/deleteVirtualNetworkOrSubnets/action"
$NetworkAdmin.Actions += "microsoft.web/serverfarms/virtualnetworkconnections/*"
$NetworkAdmin.Actions += "microsoft.web/sites/virtualnetworkconnections/*"
$NetworkAdmin.Actions += "microsoft.web/sites/networktraces/*"

# Cross-Provider Actions
$NetworkAdmin.Actions += "*/networktrace/action"

$RoleDefinitions += $NetworkAdmin		# Add to array of custom roles as final step..


# +-------------------------------------+
# |  Cloud Virtual Machine Operator		|
# +-------------------------------------+
$VMOperator = Create-NewRoleDefinition -Name "Cloud Virtual Machine Operator" `
					-Description "Allows starting & stopping of virtual machines and configuring of Insights rules and Resource Health actions"
					
$VMOperator.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
# Allow these actions
$VMOperator.Actions += "Microsoft.Storage/*/read"
$VMOperator.Actions += "Microsoft.Network/*/read"
$VMOperator.Actions += "Microsoft.ClassicNetwork/*/read"
$VMOperator.Actions += "Microsoft.ClassicStorage/*/read"

$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/performMaintenance/action"
$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/redeploy/action"
$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/restart/action"
$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/shutdown/action"
$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/start/action"
$VMOperator.Actions += "Microsoft.ClassicCompute/virtualMachines/stop/action"

$VMOperator.Actions += "Microsoft.Compute/*/read"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/start/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/restart/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/deallocate/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/redeploy/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/poweroff/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachines/performMaintenance/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/deallocate/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/performMaintenance/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/powerOff/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/redeploy/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/restart/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/start/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/deallocate/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/performMaintenance/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/powerOff/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/redeploy/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/restart/action"
$VMOperator.Actions += "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/start/action"

$VMOperator.Actions += "Microsoft.Authorization/*/read"
$VMOperator.Actions += "Microsoft.Resources/*/read"
$VMOperator.Actions += "Microsoft.Resources/deployments/*"
$VMOperator.Actions += "Microsoft.Resourcehealth/*"
$VMOperator.Actions += "Microsoft.Insights/alertRules/*"
$VMOperator.Actions += "Microsoft.Insights/*/read"
$VMOperator.Actions += "Microsoft.Support/*"

$RoleDefinitions += $VMOperator		# Add to array of custom roles as final step..


# +-----------------------------+
# |  Cloud Locks Admin			|
# +-----------------------------+
$LocksAdmin = Create-NewRoleDefinition -Name "Cloud Locks Admin" `
					-Description "Allows configuring of resource locks"
					
$LocksAdmin.Id = $null			# Set this to the GUID for the role, BUT ONLY IF THE ROLE IS ALREADY CREATED (to ensure no collisions on name)
					
$LocksAdmin.Actions += "*/read"
$LocksAdmin.Actions += "Microsoft.Authorization/locks/*"
# $LocksAdmin.Actions += "Microsoft.Support/*"

$RoleDefinitions += $LocksAdmin		# Add to array of custom roles as final step..


# +---------------------------------------------+
# |  Cloud Resource Group Contributor			|
# +---------------------------------------------+
$ResourceGroupContributor = Create-NewRoleDefinition -Name "Cloud Resource Group Contributor" `
					-Description "Allows management of resource groups, role assignments within the resource group, policy assignments, and resource locks"
					
$ResourceGroupContributor.Actions += "*/read"

# $ResourceGroupContributor.Actions += "Microsoft.Authorization/checkAccess/action"
$ResourceGroupContributor.Actions += "Microsoft.Authorization/locks/*"
$ResourceGroupContributor.Actions += "Microsoft.Authorization/policyAssignments/*"
$ResourceGroupContributor.Actions += "Microsoft.Authorization/roleAssignments/*"					# ** Highly Privileged **
$ResourceGroupContributor.Actions += "Microsoft.Resources/subscriptions/resourceGroups/*"
$ResourceGroupContributor.Actions += "Microsoft.Resources/subscriptions/TagNames/*"
$ResourceGroupContributor.Actions += "Microsoft.Resources/checkPolicyCompliance/action"
$ResourceGroupContributor.Actions += "Microsoft.Resources/checkResourceName/action"
$ResourceGroupContributor.Actions += "Microsoft.Resources/tags/*"
$ResourceGroupContributor.Actions += "Microsoft.Support/*"

$RoleDefinitions += $ResourceGroupContributor		# Add to array of custom roles as final step..



# +---------------------------------------------+
# |  Select Role(s)								|
# +---------------------------------------------+
if (!$All)
{
	write-host -ForegroundColor Yellow -NoNewLine "Please choose the role(s) to update [see popup]: "
	$RoleDefinitions = $RoleDefinitions  | Sort-Object -Property Name | Out-Gridview -Title "Please choose the role(s):" -Passthru
	write-host ""
	if ($RoleDefinitions.Count -eq 0) { return $null }
}


# +---------------------------------------------+
# |  UpdateScope								|
# | If we are just updating the scope....		|
# +---------------------------------------------+
if ($UpdateScope)
{
	write-host "UPDATE SCOPE..."
	# $RoleDefinitions are the roles; $subscriptions is the list of subscriptions
	$ReplaceAssignment = $True
	# Return  # DEBUG
}


# +---------------------------------------------+
# |  Loop through Roles							|
# |	     Loop through Subscriptions				|
# |          Define/Update role 				|
# +---------------------------------------------+

# Extract the assignable scopes from the user selection for the current tenant
# Be sure that the type remains as an array (so we loop through rather than just assign)
$SelectedSubscriptionIDs = @()
$SelectedScopes = @()
foreach ($sub in $Subscriptions)
{
	$SelectedSubscriptionIDs	+= $sub.Id
	$SelectedScopes				+= "/subscriptions/$($sub.Id)"
}

# Look for myself in the Role Assignments (so that I can verify OWNER role)
$AllOwners = @()
$AllOwners += (Get-AzRoleAssignment -RoleDefinitionName "Owner")
$AllOwners += (Get-AzRoleAssignment -RoleDefinitionName "User Access Administrator")
# Account is likely in the form first.last_Cloud.com#EXT#sdmcsandbbritishgasco.onmicrosoft.com
# TBD - This will take a lot of work to know which entry maps to the current user

# Loop through each role definition...
foreach ($role in $RoleDefinitions)
{

	$ThisRole = $null
	$NewScopes = @()

	write-host -ForegroundColor Cyan -NoNewLine "`n  Processing Role (this may be slow): "
	write-host $Role.Name
	
	# Check the custom role definition operations against provider operations
	$r = Check-ProviderOperations -CustomRole $role
	if (!$r)
	{
		write-warning "A check on the provider operations found a discrepency. If you continue, the API call will likely fail."
		$x = read-host "Type 'YES' to Continue: "
		if ($x -NotLike 'YES') { return; }
	}
	
	# Nullify the Role ID until we find a match in the tenant
	$role.Id = $null
	
	# At this point, $Subscriptions contains the selections made by the user
	# and $SelectedSubscriptionIDs contains the selected SubscriptionIds within the $tenant
	# and $SortedSubscriptions contains the list of subscriptions to search for the existing definition
	
	# Progress Counter
	$ctr = [int32] 0
	$Activity = "Searching subscriptions for existing '$($role.Name)' role definition..."
	# Loop through the subscriptions to find the role definition
	# It may or may not exist.

	if (!$NewRole)
	{
		# OPTIMIZATION: Swap the Security subscription to the top

		
		# Search for existing role definition AND make sure that we have access...
		foreach ($sub in $SortedSubscriptions)
		{
			# Progress Info
			$pctComplete = [string] ([math]::Truncate((++$ctr / $SortedSubscriptions.Count)*100))
			$Status1 = "Subscription: '$($sub.Name)' ($($sub.Id)) - $pctComplete% Complete  ($ctr of $($SortedSubscriptions.Count))"
			write-verbose "$Activity - $Status1"
			Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1

			$x = select-AzSubscription -Subscription $sub.Id -Tenant $tenant
			# $x2 = Select-AzureSubscription -SubscriptionId $sub.id -ErrorAction SilentlyContinue
			
			# Retrieve and verify our access level
			# BUT ONLY if this subscription is in the Scopes of selected
			if ($SelectedSubscriptionIDs -contains $sub.Id)
			{		
				$Account = (Get-AzContext).Account
				# write-verbose "Verifying access rights for $($Account.Id) in subscription '$($sub.Name)'  ($($sub.Id))"
				# write-verbose "Account is $($Account.Id)"  # DEBUG
				# For now, we only check the user's primary tenant
				# If the action below generates an error, then we are NOT inside the primary tenant
				$RoleAssignment = Get-AzRoleAssignment -SignInName $Account.Id -ErrorVariable Err1 -ErrorAction SilentlyContinue
				if (!$Err1 -And ($SelectedSubscriptionIDs -contains $sub.Id) -And !($RoleAssignment.RoleDefinitionName -contains "Owner") `
						   -And !($RoleAssignment.RoleDefinitionName -contains "User Access Administrator"))
				{
					# If we don't have sufficient rights , then force into WhatIf mode
					write-warning "$($Account.Id) must be an OWNER or a USER ACCESS ADMINISTRATOR in order to modify subscription '$($Sub.Name)'"
					write-verbose "Roles found for user: $($RoleAssignment.RoleDefinitionName -join '; ')"
					write-warning "Remaining actions will be processed as -WhatIf"
					$WhatIf = $True
				}
				elseif ($Err1)
				{
					# We are likely in a secondary tenant, so we should check for access.
					# So we need to map the external username back to our name...
					$Okay = $false
					foreach ($owner in $AllOwners)
					{
						$OwnerId = $owner.SignInName
						if ($OwnerId -And $OwnerId.Contains("#EXT#"))
						{
							$OwnerId = $OwnerId.SubString(0,$OwnerId.IndexOf("#EXT#"))
							$i = $OwnerId.LastIndexOf("_")
							$OwnerId = $OwnerId.SubString(0,$i) + "@" + $OwnerId.SubString($i+1)
						}
						if ($Account.Id -like $OwnerId)
						{
							$Okay = $true
							break
						}
					}
					if (!$Okay)
					{
						# If we don't have sufficient rights , then force into WhatIf mode
						write-warning "$($Account.Id) must be an OWNER or a USER ACCESS ADMINISTRATOR in order to modify subscription '$($Sub.Name)'"
						write-verbose "Subscription OWNERS: $($AllOwners.SignInName -join '; ')"
						# write-warning "Remaining actions will be processed as -WhatIf"
						# $WhatIf = $True
					}
				}
			}
			# Is the role defined in the selected subscription?
			$ThisRole = Get-AzRoleDefinition -Name $role.Name -ErrorAction SilentlyContinue
			if ($ThisRole) { break }		# Break out of the ForEach if we found it
		}
	}
	Write-Progress -Activity $Activity -PercentComplete 100 -Completed

	# Did we find the role previously defined?
	if ($ThisRole)
	{
		# We found it
		write-verbose "Found role '$($ThisRole.Name)' ($($ThisRole.Id)) in subscription: $($sub.Name)"
		$CurrentAssignableScopesTEXT = $ThisRole.AssignableScopes -join "`n  "
		write-verbose "Current Assignable Scopes: `n  $CurrentAssignableScopesTEXT"  
		$role.Id = $ThisRole.Id
		
		# If we are NOT updating the role definition, then copy
		# the existing definitions into our target $role
		if (!$DefineRole)
		{
			write-verbose "The current definition for role '$($role.Name)' will NOT be updated since -DefineRole was not specified."
			$role.Actions 			= $ThisRole.Actions
			$role.NotActions 		= $ThisRole.NotActions
			$role.DataActions 		= $ThisRole.DataActions
			$role.NotDataActions 	= $ThisRole.NotDataActions
		}
	
		# If we are only adding a new assignment, then populate
		# the $SelectedSubscriptionIDs with the existing
		$NewScopes = @()
		if ($AddAssignment)
		{
			$NewScopes = $SelectedScopes					# Start with selected scopes
			foreach ($as in $ThisRole.AssignableScopes)
			{
				if ($SelectedScopes -NotContains $as)
					{ $NewScopes += $as }
			}
		}
		elseif ($ReplaceAssignment)
		{
			$NewScopes = $SelectedScopes					# Use selected scopes
		}
		elseif ($DeleteAssignment)
		{
			foreach ($as in $ThisRole.AssignableScopes)
			{
				if ($SelectedScopes -NotContains $as)
					{ $NewScopes += $as }
			}
		}
		elseif ($DefineRole)
		{
			# If we get here, then we're simply updating an existing definition
			$NewScopes = $ThisRole.AssignableScopes
		}
		else
		{
			# We're doing a full replacement with $SelectedScopes
			$NewScopes = $SelectedScopes
		}
		
		Write-Verbose "Scopes that will be assigned:"
		if ($Verbose) { $NewScopes | ft }
	
		# Now see which scopes we're adding / removing 
		$AddedScopes = @()
		$CurrentAssignableScopes = $ThisRole.AssignableScopes
		foreach ($s in $NewScopes)
		{
			# write-host "DEBUG: Look for '$s' in $CurrentAssignableScopes"
			if ($CurrentAssignableScopes -Contains $s)
				{ $CurrentAssignableScopes = $CurrentAssignableScopes | ? {$_ -ne $s} }
			else
				{ $AddedScopes += $s }
		}
		# What remains in $CurrentAssignableScopes is the ones being removed
		if ($CurrentAssignableScopes.Count)
		{
			# $CurrentAssignableScopesTEXT = $CurrentAssignableScopes -join "`n  "   # OLD
			$CurrentAssignableScopesTEXT = ""
			foreach ($s in $CurrentAssignableScopes)
			{
				$CurrentAssignableScopesTEXT += (Get-AzSubscription -SubscriptionId $s.Replace("/subscriptions/","") -ErrorAction SilentlyContinue).Name  + "   ($s) `n"
			}
			write-warning "The following scopes are being REMOVED from the role '$($ThisRole.Name)' "
			write-host -ForegroundColor Yellow $CurrentAssignableScopesTEXT
			$r = read-host "Type 'YES' to continue or anything else to abort"
			if ($r -NotLike "YES")  { return $null }
			
			# Now Remove any role assignments within this subscription
			foreach ($s in $CurrentAssignableScopes)
			{
				write-verbose "Removing any existing role assignments in $s"
				# Note that the subscription may be deleted state...
				try
				{
					$x = Select-AzSubscription -subscription $s.Replace("/subscriptions/","") -WarningAction SilentlyContinue -ErrorAction Stop
					$Assignments = Get-AzRoleAssignment -RoleDefinitionId $role.Id
					write-verbose "   $($Assignments.Count) assignments will be removed"
					foreach ($assignment in $Assignments)
						{ $x = Remove-AzRoleAssignment -RoleDefinitionId $role.Id -ObjectId $assignment.ObjectId -Verbose }
				}
				catch
				{
					write-verbose "  Subscription appears to be in a deleted state: $s"
				}
			}
		}
		
		# Write a message about any added scopes
		if ($AddedScopes.Count -gt 0)
		{
			write-host -ForegroundColor Yellow "The following $($AddedScopes.Count) scopes are being ADDED (along with the existing scopes) to the role '$($ThisRole.Name)'"
			#  write-host ("  " + $AddedScopes -join "`n  ")   # OLD
			$CurrentAssignableScopesTEXT = ""
			foreach ($s in $AddedScopes)
			{
				$scope1 = $s.Replace('/subscriptions/','')
				$name1 = ($AllSubscriptions | Where-Object {$_.Id -like $scope1}).Name
				$CurrentAssignableScopesTEXT += $name1 + "   ($s) `n"
			}
			write-host $CurrentAssignableScopesTEXT
		}
		
		# Rename the role?
		if ($Rename)
		{
			write-host ""
			$NewName = read-host "Enter the new name for the role '$($Role.Name)'"
			if (!$NewName.Contains("Cloud "))
				{ write-warning "Role will not be renamed. Name MUST start with 'Cloud' - Aborting" ; return $null }
			else
				{ $Role.Name = $NewName }
		}
	}
	elseif ($AddAssignment -Or $ReplaceAssignment)
	{
		$NewScopes = $SelectedScopes					# Start with selected scopes
	}
	elseif ($DeleteAssignment)
	{
		write-warning "Role definition not found -- no assignment to delete!"
		return $null
	}

	
	# Clear the current AsisgnableScopes; $SelectedSubscriptionIDs has the new assignableScopes
	$role.AssignableScopes.Clear()

	# now add the assignable scopes $NewScopes for the tenant
	# NOTE: we don't fully check to see if the selected scopes CAN be added... Some subscriptions are in a weird state.
	if ($Check)  { write-host "Checking status of selected scopes (This is slow!)..." }
	foreach ($scope in $NewScopes)
	{
		# If selected, check the status of each subscription by retrieving the 'Reader' role definition
		if ($Check)
		{
			write-verbose "Checking $scope"
			$scope1 = $scope.Replace('/subscriptions/','')
			$name1 = ($AllEnabledSubscriptions | Where-Object {$_.Id -like $scope1}).Name
			try 
			{
				$Err1 = $null
				$x = Select-AzSubscription -Subscription $scope1 -ErrorAction Stop -ErrorVariable Err1
				$x = Get-AzRoleDefinition -Name "Reader" -ErrorAction Stop -ErrorVariable Err1
				$role.AssignableScopes += $scope
			}
			catch
			{
				write-warning "Subscription $name1 ($scope1) has caused an error - Check failed - Skipping this scope"
				write-host $Err1.Exception.Message
			}
		}
		else
		{
			# No checking is performed
			$role.AssignableScopes += $scope
		}
	}
	
	# Now update the role definition if it exists
	# Otherwise create this as a new role
	if ($role.Id)
	{
		# update existing role
		if ($WhatIf)
		{
			write-host -ForegroundColor Cyan "    WHATIF: Updating EXISTING role '$($role.Name)' within tenant"			
		}
		else
		{
			write-host -ForegroundColor Cyan "    Updating EXISTING role '$($role.Name)' within tenant"
			if ($Check)
			{
				r = read-host "Type 'YES' to continue or anything else to abort"
				if ($r -NotLike "YES")  { return $null }
			}
			$Err1 = $null
			# Get-PSBreakpoint | Remove-PSBreakpoint;
			# Set-PSBreakpoint -Command Set-AzRoleDefinition -Action { if ($Err1) { break; } };
			$x = Set-AzRoleDefinition -Role $role -ErrorVariable Err1 -ErrorAction Stop  -Debug
			if ($Err1) { return $null }
		}
	}
	elseif ($DefineRole)
	{
		# Make sure we have scopes
		if ($NewScopes.Count -eq 0)
		{
			write-warning "This appears to be a NEW custom role definition."
			write-warning "You must use -DefineRole and -AddAssignment switches together."
			return $null
		}
	
		Write-Verbose "Scopes that will be assigned to the new role:"
		if ($Verbose) { $NewScopes | ft }

		# Define new role
		if ($WhatIf)
		{
			write-host -ForegroundColor Cyan "    WHATIF: Defining NEW role '$($role.Name)' within tenant"			
		}
		else
		{
			write-host -ForegroundColor Cyan -NoNewLine "    Defining NEW role '$($role.Name)' within tenant "
			$Err1 = $null
			$x = New-AzRoleDefinition -Role $role -ErrorVariable Err1 -ErrorAction Stop 
			write-host "- $($x.Id) assigned"
		}
	}
	else
	{
		write-warning "Role definition for '$($role.Name)' was not found and -DefineRole was not specified."
	}
}



		