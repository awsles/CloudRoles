#Requires -Version 5
<#
.SYNOPSIS
	Copy-AwsRole: Copies one or more role definitions from one AWS account to another.
.DESCRIPTION
	This script takes roles definitions as input files and then applies
	those definitions to selected AWS accounts. The input files may have
	embedded comments (which are stripped before the policy is applied).
	The comments are used to create the policy description.
	
	The policy definitions must exist in the target. If they don't exist, the
	user is prompted to select the policy(s) to apply to the role.
	
	The list of accounts may be in 'AWS_Accounts.csv' in the current directory
	with the 1st line as 'AccountNumber,AccountName,RoleNamePrefix,Owner'.
	
	The remote AWS accounts must have a role 'CloudBootstrapper' with
	a trust relationship to the AWS user account in which this script is run.
	
.PARAMETER Rename
	By default, the prefix of roles names are renamed if they match the general
	naming convention for the source subscription (as based in the AWS acocunt CSV).
	For example, "PreProd-xyz" will be renamed to "Prod-xyz" if the target is a production account.
	This feature is a bit haphazzard and here as a convenience.  The bets practice is to keep the
	policy names consistent across environments.
	
.PARAMETER LocalGitRepo
	Specifies the path to the local synchronize git repository for Cloud Roles.

.NOTES
	Author: Lester Waters
	Version: v0.20
	Date: 13-Jul-21
	
	TO DO:  (1) Verify that th referenced policies and boundary permissions exist in the target
	account before creating the role. (2) Support roles with In-Line policies. (3) Optionally
	copy and dependent policies which don't already exist in the target account(s).
	(4) Optionally display role and policy definition via -Display switch.
	
.LINK

#>

# +=================================================================================================+
# |  PARAMETERS																						|
# +=================================================================================================+
[cmdletbinding()]   #  Add -Verbose support; use: [cmdletbinding(SupportsShouldProcess=$True)] to add WhatIf support
Param 
(
	[Parameter(Mandatory=$false)] [switch] $Rename				= $true,		# If true, policy is renamed where prefix matches
	[Parameter(Mandatory=$false)] [string] $LocalGitRepo 		= ''	# Local Sync'd Repo
)

# Determine if -verbose was specified
$Verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

# Ensure we have a trailing slash on $LocalGitRepo
if ( [char]$LocalGitRepo[-1] -ne [char] '\')
	{ $LocalGitRepo += '\' }
$LocalGitRepo += 'AWS\'		# Add AWS Folder reference within Git Repo


# +=================================================================================================+
# |  EXTERNAL SCRIPTS & MODULES																		|
# +=================================================================================================+
$CurrentVerbosePreference = $VerbosePreference
$VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
$Activity = "Importing PowerShell Modules..."
Write-Progress -Activity $Activity -PercentComplete 10
Import-Module -Name AWSPowerShell
[System.Reflection.Assembly]::LoadWithPartialName("System.web")		# Needed for URLDecode
$VerbosePreference = $CurrentVerbosePreference

# Get Current directory (PowerShell scripts seem to default to the Windows System32 folder)
$invocation 	= (Get-Variable MyInvocation).Value
$directoryPath 	= Split-Path $invocation.MyCommand.Path
[IO.Directory]::SetCurrentDirectory($directorypath)   	# Set current directory

# Load the script using DOT notation
# . "$directoryPath\AzureFunctionLibrary.ps1"				# Provides output libraries
Write-Progress -Activity $Activity -PercentComplete 100 -Completed


# +=================================================================================================+
# |  CONSTANTS																						|
# +=================================================================================================+
$AWSAccountsCSV			= 'AWS_Accounts.csv'
$AWSRolesFile			= 'AWS-Roles.json'
$ExternalID 			= 'XXXXXXXXXXXXXX'		# Required to sts:AssumeRole
$SAMLProviderDefault	= 'arn:aws:iam::%%AccountID%%:saml-provider/XXXXXXXXXXXXXXXX'

# AD Group Settings
# $ADGroupOU_UK		= 'OU=AWSRoles,OU=MGMTPortals,OU=CloudServices,OU=Groups,DC=uk,DC=COMPANY,DC=com'
# $ADGroupManagedBy	= 'XXXXXXXXXXX'  

# Miscellaneous
$crlf 					= [char]13 + [char]10

# AssumeRolePolicyDocumentTemplate -- This is the standard definition for the SAML provider used for all assumable roles
# %SAMLProviderARN% is the placeholder for the ARN.

$AssumeRolePolicyDocumentTemplate = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"%SAMLProviderARN%"},"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}'
$MoreInformation = "
This AD group is required for SAML access into AWS.`n
The OU is: OU=Role-Groups,OU=Cloud-Services,OU=Groups,DC=uk,DC=COMPANY,DC=com.`n
The 'info' field of the new AD groups should be: **Restricted**
`n"	
		

# +=================================================================================================+
# |  CLASS DEFINITIONS																				|
# +=================================================================================================+

Class	RoleDefinition
{
	[string]	$RoleName
	[string]	$Description
	[string]	$Path						# '/'
	[string]	$PermissionsBoundary		# The ARN of the policy that is used to set the permissions boundary for the role.
	[string]	$AssumeRolePolicyDocument	# [System.Web.HttpUtility]::UrlEncode($AssumeRolePolicyText)
	[string]	$AssumeRolePolicyText		#
	[int32]		$MaxSessionDuration			# 1 to 12 hours specified in seconds
	[PSObject]	$AttachedPolicies			# {PolicyArn,PolicyName}
	[PSObject]	$Tags
}



# +=================================================================================================+
# |  FUNCTIONS																						|
# +=================================================================================================+

# +-------------------------------------------------------------------------+
# |  ValidDescription()														|
# |  Returns a description suitable for AWS, dropping extra characaters.	|																		|
# +-------------------------------------------------------------------------+
function ValidDescription { 
param
(
	[string] $Description,		# Input text
	[string] $Title				# What is this for?  Displayed in the event of an error only
)
	# Ensure Description is compliant
	# [System.IO.Path]::GetInvalidFileNameChars() | % {$text = $text.replace($_,'.')}
	$NewDescription = ""
	$ValidChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789+=,.@-_'				# $String -match '[^a-zA-Z0-9+=,.@-_]'
	# $SpecialChars = "#?()[]{}"							# We need to find these in the string
	# $rePattern = ($SpecialChars.ToCharArray() |ForEach-Object { [regex]::Escape($_) }) -join "|"
	foreach ($char in [char[]]$Description)
	{
		if ( $ValidChars.Contains($char))
			{ $NewDescription += [string]$char }
	}
	
	# Check Length < 1000
	if ($NewDescription.Length -gt 1000)
	{ 
		$NewDescription = $NewDescription.SubString(0,1000)
		write-warning "Description has been truncated to 1000 characters for $Title"
	}

	Return $NewDescription.Trim()
}

# +=================================================================================================+
# |  MAIN BODY																						|
# +=================================================================================================+
$ADGroups = @()
$PRVcredentialAsk = $false


# +---------------------------------------------+
# |  AWS Authentication							|
# +---------------------------------------------+
# Set-AWSCredential -AccessKey AKIAUZLSCVVKBADDSKFA -SecretKey xxxxxxxxxxxxxxxxxxxxx -StoreAs Bootstrapper
Initialize-AWSDefaults -ProfileName Bootstrapper -Region eu-west-2
Set-AWSCredential -ProfileName Bootstrapper

Try
{
    $x = $CallerID = Get-STSCallerIdentity -ErrorVariable Err1 -ErrorAction Stop		# .Account, .Arn, .UserId
	write-host -ForegroundColor Cyan "`nAWS Login as $($x.Arn) ($($x.UserId)) via account $($x.Account)"
}
Catch
{
    write-output $Err1[0].Message
    if ($Err1[0].HResult -eq -2146233087 -And $Err1[0].Message.Contains('roxy'))
		{ write-warning "Bad Proxy (407 Authentication Required)... Try again!" }
    return $null
}


# +---------------------------------------------+
# |  Get Organizational Info					|
# +---------------------------------------------+
$OrgInfo = Get-OrgOrganization -ProfileName Bootstrapper
write-host "Master Account is $($OrgInfo.MasterAccountId) ($($OrgInfo.MasterAccountEmail))"
If ($CallerId.Account -Like $OrgInfo.MasterAccountId)
{
	$UseOrg = $true 	# Determine account list via AWS Organizations
}
elseif (!$OrgInfo)
{
	write-warning "No data returned from Get-Organization cmdlet."
	$UseOrg = $false	# Determine account list via CSV file
}
else
{
	write-warning "You are running this script in $($CallerId.Account) which is outside the Master account`nYou may not be able to see all subordinate AWS accounts."
	$UseOrg = $false	# Determine account list via CSV file
}	

# WARNING
write-warning "Roles with in-line policies are NOT supported at this time!`n"

# +---------------------------------------------+
# |  Ingest list of AWS Accounts				|
# +---------------------------------------------+
# Unless this script is run from the Master account, there is no way (I know of)
# to enumerate the full set of AWS account numbers and names.
# The work-around is to read in a CSV file containing this information
# with the 1st line as 'AccountNumber,AccountName,RoleNamePrefix,Owner'

# Locate the AWS_Accounts.csv file... (prefer git location, folder by current directory)
$AWSAccountsFile = $LocalGitRepo + $AWSAccountsCSV
$PolicyFolder = $LocalGitRepo + 'AWS\'
if (!(test-path -Path $AWSAccountsFile))
{
	$AWSAccountsFile = $directoryPath + '\' + $AWSAccountsCSV
	$PolicyFolder = [Environment]::GetFolderPath('Desktop')
	if (!(test-path -Path $AWSAccountsFile))
	{
		write-warning "Unable to locate '$AWSAccountsCSV'. Expected to find it in $LocalGitRepo."
		return
	}
}

write-verbose "Reading AWS accounts from '$AWSAccountsFile'"
$AWSAccountsList		= @()
$AWSAccounts1 	= (Get-Content -Raw -Path $AWSAccountsFile) | ConvertFrom-CSV
# Ensure Account number is exactly 12 digits
foreach ($AWSAccount in $AWSAccounts1)
{
	$AWSAccount.AccountNumber = ([Int64]$AWSAccount.AccountNumber).ToString('000000000000')
	if ($AWSAccount.AccountNumber.Length -ne 12)
		{ write-warning "Invalid AWS Account '$($AWSAccount.AccountNumber)' in '$AWSAccountsCSV'"	}
	elseif ($AWSAccount.AccountNumber -ne '000000000000')
		{ $AWSAccountsList += $AWSAccount }
}


# +---------------------------------------------+
# |  Select Source AWS Account					|
# +---------------------------------------------+
$Msg = "Select source AWS account"
write-host -ForegroundColor Yellow -NoNewLine "$Msg (See Popup): "
$AWSSourceAccounts	= @()
$AWSSourceAccounts 	= @($AWSAccountsList | Out-GridView -Title $Msg -Passthru)
# $AWSSourceAccounts[0].RoleNamePrefix
write-Host ""
if ($AWSSourceAccounts.Count -eq 0)
{
	write-host "No source AWS account selected."
	Return
}
elseif ($AWSSourceAccounts.Count -ne 1)
{
	write-warning "Only ONE source account may be selected."
	Return
}
write-host "  Source Account: $($AWSSourceAccounts[0].AccountNumber)"

	
# +---------------------------------------------+
# | sts:AssumeRole to Source AWS Account 		|
# +---------------------------------------------+
# Ensure Account number is exactly 12 digits (recheck)
$SrcAWSAccountId = $AWSSourceAccounts[0].AccountNumber
$SrcAWSAccountId = ([Int64]$SrcAWSAccountId).ToString('000000000000')
if ($SrcAWSAccountId.Length -ne 12)
	{ write-warning "Invalid AWS Account '$SrcAWSAccountId' in '$AWSTargetAccountsCSV'" ; Return	}

# Prepare for sts:AssumeRole
# $AWSAccountId = '214667173281'
$RoleARN = 'arn:aws:iam::' + $SrcAWSAccountId + ':role/CloudBootstrap'
Write-Verbose "Assuming role '$RoleArn'"
$Result = Use-STSRole -RoleArn $RoleArn -ExternalId $ExternalId -RoleSessionName "BootstrapSession" -Verbose 
$Creds = $Result.Credentials
# $Creds is an object that now contains the AccessKeyId, SecretAccessKey, and SessionToken elements that you need in the following steps.
# Use the -Credentials $Creds in the PowerShell cmdlets: get-iamroles -Credential $Creds


# +---------------------------------------------+
# | Get role definitions from source account	|
# +---------------------------------------------+
# Get the list of currently defined roles
$SourceRoles = @(Get-IamRoleList -Credential $creds)
$ChosenRoles = ($SourceRoles | Sort-Object -Property PolicyName `
						| Select-Object -Property RoleName,Description,PermissionBoundary,Path,MaxSessionDuration,Arn,RoleId,Tags `
						| Out-GridView -Title "Choose role(s) to copy..." -PassThru)
if ($ChosenRoles.Count -eq 0)
{
	write-host "No roles chosen!"
	return
}
ForEach ($role in $ChosenRoles)
{
	$Index = $SourceRoles.RoleId.IndexOf($role.RoleId)
	
	# Policy Document
	# Drop out any reference to current account and replace with %%AccountID%% for later substitution
	$PolicyDocument = [System.Web.HttpUtility]::UrlDecode($SourceRoles[$index].AssumeRolePolicyDocument)
	$PolicyDocument = $PolicyDocument.Replace($SrcAWSAccountId, '%%AccountID%%')
	
	$role | Add-Member -NotePropertyName 'AssumeRolePolicyDocument' `
						-NotePropertyValue $PolicyDocument
	$AttachedPolicies = Get-IamAttachedRolePolicyList -RoleName $SourceRoles[$Index].RoleName -Credential $Creds
	# Drop out Account Number and insert %%AccountID%%
	$AttachedPoliciesTxt = ($AttachedPolicies | ConvertTo-json -Compress -Depth 5).Replace($SrcAWSAccountId, '%%AccountID%%')
	$role | Add-Member -NotePropertyName 'AttachedPolicies' -NotePropertyValue $AttachedPoliciesTxt
}


# +---------------------------------------------+
# |  Select Target AWS Account					|
# +---------------------------------------------+
$AWSTargetAccounts	= @()
$Msg = "Select target AWS account"
write-host -ForegroundColor Yellow -NoNewLine "$Msg (See Popup): "
$AWSTargetAccounts = @($AWSAccountsList | Out-GridView -Title $Msg -Passthru)
write-Host "  $($AWSTargetAccounts.Count) target account(s) selected."
if ($AWSTargetAccounts.Count -eq 0)
{
	write-host "No target AWS account(s) selected."
	Return
}
write-host "  Target Account(s): $($AWSTargetAccounts.AccountNumber -join ', ')`n"


# +-----------------------------------------------------------------------------+
# |  Process each target AWS account											|
# +-----------------------------------------------------------------------------+
$ctr = [int32] 0
foreach ($AWSAccount in $AWSTargetAccounts)
{
	$pctComplete = [string] ([math]::Truncate((++$ctr / $AWSTargetAccounts.Count)*100))
	
	# Ensure Account number is exactly 12 digits (recheck)
	$AWSAccountId = $AWSAccount.AccountNumber
	$AWSAccountId = ([Int64]$AWSAccountId).ToString('000000000000')
	if ($AWSAccountId.Length -ne 12)
		{ write-warning "Invalid AWS Account '$AWSAccountId' in '$AWSTargetAccountsCSV'"	}
		
	# Progress
	$Activity = "Apply policies to Account $AWSAccountID"
	write-host -ForegroundColor Cyan "`n==== AWS Account: $AWSAccountId ===="

	# Make sure Source != Target Account
	if ($SrcAWSAccountId -like $AWSAccountId)
	{
		write-warning "Target account $AWSAccountId cannot be the same as the source account - skipping."
		continue;
	}

	# Prepare for sts:AssumeRole
	$RoleARN = 'arn:aws:iam::' + $AWSAccountId + ':role/CloudBootstrap'
	Write-Verbose "Assuming role '$RoleArn'"
	$Result = Use-STSRole -RoleArn $RoleArn -ExternalId $ExternalId -RoleSessionName "BootstrapSession" -Verbose 
	$Creds = $Result.Credentials
	# $Creds is an object that now contains the AccessKeyId, SecretAccessKey, and SessionToken elements that you need in the following steps.
	# Use the -Credentials $Creds in the PowerShell cmdlets: get-iamroles -Credential $Creds


	# +---------------------------------------------+
	# | Get role definitions from target account	|
	# +---------------------------------------------+
	# Get the list of currently defined roles
	$TargetRoles = @(Get-IamRoleList -Credential $creds)

	# +---------------------------------------------+
	# | Apply each Role Definition					|
	# +---------------------------------------------+
	foreach ($role in $ChosenRoles)
	{
		# Determine the proposed role name and Description
		$ProposedRoleName = $role.RoleName
		$RoleDescription = ValidDescription -Description $role.Description -Title "Role '$ProposedRoleName'"

		# Progress bar...
		$Status1 = "Defining Role '$ProposedRoleName' - $pctComplete% Complete  ($ctr of $($AWSAccounts.Count))"
		Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1
		write-host -ForegroundColor Cyan "  Role: $ProposedRoleName"
		
		# Do Substitutions on %%AccountID%%
		$TargetPolicies = @()
		$AttachedPolicies = @()
		$AttachedPolicies = ($role.AttachedPolicies | ConvertFrom-Json -ErrorAction SilentlyContinue)
		foreach ($policy in $AttachedPolicies)
		{
			$Policy1 = ($policy | ConvertTo-Json | ConvertFrom-Json)
			$Policy1.PolicyArn = $Policy1.PolicyArn.Replace('%%AccountID%%', $AWSAccountID)
			$TargetPolicies += $policy1
		}
		
		# If the role already exists, then warn the user as we cannot update existing roles YET
		if ($TargetRoles.RoleName -Contains $ProposedRoleName)
		{
			write-warning "The role '$ProposedRoleName' already exists in AWS account $AWSAccountId."
			
			# Determine the set of attached policies on the existing role
			# https://docs.aws.amazon.com/powershell/latest/reference/items/Get-IAMAttachedRolePolicyList.html
			$CurrentAttachedPolicies = Get-IAMAttachedRolePolicyList -RoleName $ProposedRoleName -MaxItem 100 -Credential $Creds
			# $CurrentAttachedPolicies = Get-IAMAttachedRolePolicyList -RoleName devtest-DL-CBS-SecurityAdmin -Credential $Creds 

			write-host "  Current Attached Policies: $($CurrentAttachedPolicies.PolicyName -join ', ')"
			write-host "  New Policies from Source Account: $($TargetPolicies.PolicyName -join ', ')"
			$r = read-host "Update $ProposedRoleName policy assignments from source account? ['YES' to confirm]"
			if ($r -like 'yes')
			{
				$PoliciesToAdd = @($TargetPolicies | Where-Object { $CurrentAttachedPolicies.PolicyArn -NotContains $_.PolicyArn})
				$PoliciesToAddTxt = $PoliciesToAdd.PolicyName -join ", "
				$PoliciesToRemove = @($CurrentAttachedPolicies | Where-Object { $TargetPolicies.PolicyArn -NotContains $_.PolicyArn})
				$PoliciesToRemoveTxt = $PoliciesToRemove.PolicyName -join ", "
				$PoliciesToKeep = @($CurrentAttachedPolicies | Where-Object { $TargetPolicies.PolicyArn -Contains $_.PolicyArn})
				$PoliciesToKeepTxt = $PoliciesToKeep.PolicyName -join ", "
				if ($PoliciesToKeep)
					{ write-host "  Keeping existing policies on role $ProposedRoleName : $PoliciesToKeepTxt" }
				if ($PoliciesToRemove)
				{
					write-host "  Removing policies from role $ProposedRoleName : $PoliciesToRemoveTxt"
					foreach ($policy in $PoliciesToRemove)
					{
						$r = Unregister-IAMRolePolicy -RoleName $ProposedRoleName -PolicyArn $policy.PolicyArn -Credential $Creds -ErrorAction Stop # -Force 
					}
				}
				if ($PoliciesToAdd)
				{
					write-host "  Adding Policies to role $ProposedRoleName : $PoliciesToAddTxt"
					foreach ($policy in $PoliciesToAdd)
					{
						$r = Register-IAMRolePolicy -RoleName $ProposedRoleName -PolicyArn $policy.PolicyArn -Credential $Creds -ErrorAction Stop # -Force 
					}
				}
				
				# Update Tags
				# Tags are NOT updated in this case!
			}
		}
		else
		{
			# Create the role
			# https://docs.aws.amazon.com/powershell/latest/reference/items/New-IAMRole.html
			write-host -ForegroundColor Yellow "  Creating new role '$ProposedRoleName' in AWS account $AWSAccountId"
			$r = New-IamRole -RoleName $ProposedRoleName -Description $RoleDescription -MaxSessionDuration $role.MaxSessionDuration `
							-AssumeRolePolicyDocument $role.AssumeRolePolicyDocument `
							-PermissionsBoundary $role.PermissionBoundary -Credential $Creds -ErrorAction Stop  # -Tag  $AssumeRolePolicyDocumentEncoded
			
			# Attach the policies
			# https://docs.aws.amazon.com/powershell/latest/reference/items/Register-IAMRolePolicy.html
			# TBD
			$PoliciesToAdd = $TargetPolicies
			$PoliciesToAddTxt = $PoliciesToAdd.PolicyName -join ", "
			if ($PoliciesToAdd)
			{
				write-host "  Adding Policies to role $ProposedRoleName : $PoliciesToAddTxt"
				foreach ($policy in $PoliciesToAdd)
				{
					$r = Register-IAMRolePolicy -RoleName $ProposedRoleName -PolicyArn $policy.PolicyArn -Credential $Creds -ErrorAction Stop # -Force 
				}
			}
			
			# Attach the Tags
			# TBD  Add-IamRoleTag
		}
	} # foreach $Role
} # foreach $AWSAccount
Write-Progress -Activity $Activity -PercentComplete 100 -Completed

write-host "Done!`n"

