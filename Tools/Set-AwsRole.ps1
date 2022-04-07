#Requires -Version 5
<#
.SYNOPSIS
	Creates/updates policy & role definitions across multiple AWS accounts.
.DESCRIPTION
	This script takes policy definitions as input files and then applies
	those definitions to selected AWS accounts. The input files may have
	embedded comments (which are stripped before the policy is applied).
	The comments are used to create the policy description.
	
	The list of accounts may be in 'AWS_Accounts.csv' in the current directory
	with the 1st line as 'AccountNumber,AccountName,AccountType,RoleNamePrefix,Owner'.
	
	The remote AWS accounts must have a role 'CloudBootstrapper' with
	a trust relationship to the AWS user account in which this script is run.
	
.PARAMETER useCSVnameprefix
	If specified, then the existing groupname as found in Active Directory
	(e.g, g-CloudAdmin group) is ignored and
	the name prefix as specified in the input CSV is used.
	
.PARAMETER LocalGitRepo
	Specifies the path to the local synchronize git repository for Cloud Roles.

.PARAMETER Force
	If specified, then existing policy and role definitions are deleted
	before the new definition is created.  Otherwise, only the policy version is updated.
	
.NOTES
	Author: Lester Waters
	Version: v0.56
	Date: 13-Jul-21
		
	NOTE: This script does not set or update the SAML Identity Provider in AWS.  

.LINK

#>
# AWS sts:AssumeRole test
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-twp.html
# https://docs.aws.amazon.com/powershell/latest/reference/index.html
# https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
#

# +=================================================================================================+
# |  PARAMETERS																						|
# +=================================================================================================+
[cmdletbinding()]   #  Add -Verbose support; use: [cmdletbinding(SupportsShouldProcess=$True)] to add WhatIf support
Param 
(
	[Parameter(Mandatory=$false)] [switch] $useCSVnameprefix	= $false,		# If true, then force re-creation of Policy
	[Parameter(Mandatory=$false)] [string] $LocalGitRepo 		= '',	# Local Sync'd Repo
	[Parameter(Mandatory=$false)] [switch] $Force				= $false		# If true, then force re-creation of Policy
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
[System.Reflection.Assembly]::LoadWithPartialName("System.web")
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
$ADGroupInfo		= '**Restricted**'


# Miscellaneous
$crlf 					= [char]13 + [char]10

# AssumeRolePolicyDocumentTemplate -- This is the standard definition for the SAML provider used for all assumable roles
# %SAMLProviderARN% is the placeholder for the ARN.

$AssumeRolePolicyDocumentTemplate = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"%SAMLProviderARN%"},"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}'
$MoreInformation = "
This AD group is required for SAML access into AWS.`n
The OU is: OU=Role-Groups,OU=Cloud-Services,OU=Groups,DC=uk,DC=COMPANY,DC=com.`n"	
		

# +=================================================================================================+
# |  CLASS DEFINITIONS																				|
# +=================================================================================================+

Class	PolicyDefinition
{
	[string]	$PolicyName
	[string]	$Description
	[string]	$PolicyDocument
	[int32]		$PolicyLength
	[PSObject]	$PolicyJSON
	[string]	$PolicyJSONtext
}

Class	RoleDefinition
{
	[string]	$RoleName
	[string]	$Description
	[string]	$Scope						# '/'
	[string]	$RoleType
#	[string]	$PermissionsBoundary		# The ARN of the policy that is used to set the permissions boundary for the role.
#	[string]	$AssumeRolePolicyDocument	# [System.Web.HttpUtility]::UrlEncode($AssumeRolePolicyText)
#	[string]	$AssumeRolePolicyText		#
#	[int32]		$MaxSessionDuration			# 1 to 12 hours specified in seconds
#	[PSObject]	$AttachedPolicies			# {PolicyArn,PolicyName}
#	[PSObject]	$Tags
}

Class	AdGroup
{
	[string]	$Name
	[string]	$Description
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

# Authenticate to proxy
# https://stackoverflow.com/questions/14263359/access-web-using-powershell-and-proxy
$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials 
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

Try
{
    $CallerID = Get-STSCallerIdentity -ErrorVariable Err1 -ErrorAction Stop		# .Account, .Arn, .UserId
}
Catch
{
    write-warning "ERROR: $($Err1[0].Message)"
    if ($Err1[0].HResult -eq -2146233087 -And $Err1[0].Message.Contains('(407)'))
		{ write-warning "Bad Proxy... Try again!" }
    return $null
}


# +---------------------------------------------+
# |  Get Organizational Info					|
# +---------------------------------------------+
# NOT IN USE... we have multiple organizations! So use CSV.
# $OrgInfo = Get-OrgOrganization -ProfileName Bootstrapper -ErrorAction SilentlyContinue -WarningActionSilentlyContinue
If ($CallerId.Account -Like $OrgInfo.MasterAccountId)
{
	write-host "Master Account is $($OrgInfo.MasterAccountId) ($($OrgInfo.MasterAccountEmail))"
	$UseOrg = $true 	# Determine account list via AWS Organizations
}
elseif (!$OrgInfo)
{
	write-warning "No data returned from Get-Organization cmdlet."
	$UseOrg = $false	# Determine account list via CSV file
}
else
{
	write-host "Master Account is $($OrgInfo.MasterAccountId) ($($OrgInfo.MasterAccountEmail))"
	write-warning "You are running this script in $($CallerId.Account) which is outside the Master account`nYou may not be able to see all subordinate AWS accounts."
	$UseOrg = $false	# Determine account list via CSV file
}
$UseOrg = $false	# NOT IN USE

# +---------------------------------------------+
# |  Select AWS Account(s)						|
# +---------------------------------------------+
# Unless this script is run from the Master account, there is no way (I know of)
# to enumerate the full set of AWS account numbers and names.
# The work-around is to read in a CSV file containing this information
# with the 1st line as 'AccountNumber,AccountName,RoleNamePrefix,Owner'

# Locate the AWS_Accounts.csv file... (prefer git location, folder by current directory)
$AWSAccountsFile = $LocalGitRepo + $AWSAccountsCSV
$PolicyFolder = $LocalGitRepo
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

write-host ""
$Msg = "Select target AWS account(s)"
write-verbose "Reading AWS accounts from '$AWSAccountsFile'"
write-host -ForegroundColor Yellow -NoNewLine "$Msg (See Popup): "
$AWSAccounts = @()
$AWSAccounts1 = (Get-Content -Raw -Path $AWSAccountsFile) | ConvertFrom-CSV
# Ensure Account number is exactly 12 digits
foreach ($AWSAccount in $AWSAccounts1)
{
	$AWSAccount.AccountNumber = ([Int64]$AWSAccount.AccountNumber).ToString('000000000000')
	if ($AWSAccount.AccountNumber.Length -ne 12)
		{ write-warning "Invalid AWS Account '$($AWSAccount.AccountNumber)' in '$AWSAccountsCSV'"	}
	elseif ($AWSAccount.AccountNumber -ne '000000000000')
		{ $AWSAccounts += $AWSAccount }
}
$AWSAccounts = @($AWSAccounts | Out-GridView -Title $Msg -Passthru)
write-Host "  $($AWSAccounts.Count) accounts selected"
if ($AWSAccounts.Count -eq 0)
{
	write-host "No target AWS account(s) selected."
	Return
}


# +---------------------------------------------+
# |  Select Policy files						|
# +---------------------------------------------+
# Select Policy file(s)
write-host -ForegroundColor Yellow -NoNewLine "Please choose the policy JSON files to apply (see popup): "
# https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
						InitialDirectory = $PolicyFolder
						Filter = 'JSON Files (*.json)|*.json|Text (*.txt)|*.txt|All Files (*.*)|*.*'
						Multiselect = $true	}
$null = $FileBrowser.ShowDialog()	# show the dialog box
$FilePaths = $FileBrowser.FileNames
if ($FilePaths.Count -eq 0)
	{ Write-host " No files selected." ; Return }
else
	{ Write-host " $($FilePaths.Count) files chosen." }
	

# +---------------------------------------------+
# |  Ingest Policy files						|
# +---------------------------------------------+
# Read in each selected policy
$ctr = [int32] 0
$Activity = "Reading Policy Definitions"
$PolicyDefinitions = @()
foreach ($file in $FilePaths)
{
	# Determine the policy name (based on the input file name; case is preserved)
	$PolicyName = [io.path]::GetFileNameWithoutExtension($(Split-Path $file -leaf))
#	if ($PolicyName.ToLower().StartsWith('aws-'))   { $PolicyName = $PolicyName.SubString(4) }	# drop 'aws-' prefix if present
#	if ($PolicyName.ToLower().StartsWith('azure-')) { write-warning "Only AWS policies may be used - '$PolicyName' is invalid - aborting" ; Return; break; }

	# Progress bar...
	$pctComplete = [string] ([math]::Truncate((++$ctr / $FilePaths.Count)*100))
	$Status1 = "Policy '$PolicyName' - $pctComplete% Complete  ($ctr of $($FilePaths.Count))"
	Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1	

	# Read the policy file...
	$PolicyDoc = Get-Content -Path $file
	
	# // Strip out any comments
	$PolicyTxt = ""
	$Description = ""
	foreach ($line in $PolicyDoc)
	{
		$line = $line.Replace('//','\\')		# Interchangable comments either // or \\
		if ($line.IndexOf('\\') -eq 0)
		{ 
			# // Line starts with a comment... 
			# If we haven't seen any JSON, then we can add to our Description
			if ($PolicyTxt.Trim().Length -le 2)
			{
				#We will extract the comment and use as a Description
				$Description += $line.SubString(2).Trim() + ' '
				# Drop anything after 'NOTE:' (we don't include it in the description)
				if ($Description.Contains('NOTE:'))
					{ $Description = $Description.SubString(0,$Description.IndexOf('NOTE:')) }
			}
		}
		elseif ($line.IndexOf('\\') -ge 1)
		{ 
			$LineSubset = "$($line.SubString(0,$line.IndexOf('\\')))`n"
			if ($LineSubset.Trim().Length -gt 0) { $PolicyTxt += $LineSubset }
		}
		else
			{ $PolicyTxt += "$line`n" }
	}
	
	# Convert to an object & check json syntax & length
	# Substitute <ACCOUNT_NUMBER> to %%AccountID%% (which is subsituted later in the policy definition
	$PolicyTxt = $PolicyTxt.Trim().Replace('<ACCOUNT_NUMBER>','%%AccountID%%')

    Try
    {
	    $PolicyJSON = $PolicyTxt | ConvertFrom-Json -ErrorAction Stop -ErrorVariable Err1
    }
    Catch
    {
        write-warning "Error in JSON $PolicyName : `n$($Err1[0].Message)"
        # write-output $Err1[0].Message
        write-warning "Error in JSON... aborting!"
        return $null
    }
	# Strip out PolicyName and PolicyDescription
	if ($PolicyJSON.PolicyName) { $PolicyName = $PolicyJSON.PolicyName.Trim() }
	if ($PolicyJSON.PolicyDescription) { $Description = $PolicyJSON.PolicyDescription.Trim() }
	$PolicyJSON = ($PolicyJSON | Select-Object -Property Version,Statement)
	$PolicyTxt = ($PolicyJSON | ConvertTo-Json -Depth 5)

	
	# Validate Length
	$PolicyLength = ($PolicyJSON | ConvertTo-Json -Compress ).Length
	write-Verbose "  Policy '$PolicyName' Length is $PolicyLength"
	if ($PolicyLength -gt 6144)
		{ write-host "Policy $PolicyName exceeds the limit 6144 characters." }
	
	# Ensure Description is compliant
	$Description = ValidDescription -Description $Description -Title "Policy '$PolicyName'"
	# Remove PolicyName from start of Description (typically is 1st comment line in file)
	if ($Description -like "$PolicyName *")
	{
		$Description = $Description.SubString($PolicyName.Length).Trim()
	}
	
	# Create Object
	$Entry = New-Object PolicyDefinition
	$Entry.PolicyName		= $PolicyName
	$Entry.Description		= $Description
	$Entry.PolicyDocument	= $PolicyTxt
	$Entry.PolicyJSON		= $PolicyJSON
	$Entry.PolicyLength		= $PolicyLength
	$Entry.PolicyJSONtext	= $PolicyJSON | ConvertTo-Json  
	$PolicyDefinitions += $Entry
}
Write-Progress -Activity $Activity -PercentComplete 100 -Completed

# +---------------------------------------------+
# |  Ingest Role Definition file				|
# +---------------------------------------------+
$Activity = "Reading Role Definitions from $AWSRolesFile..."
Write-Progress -Activity $Activity -PercentComplete 10 	
# Read the role file... (look in same folder as policies)
$PolicyFolder = [io.path]::GetDirectoryName($FilePaths[0])
if (!($PolicyFolder[-1] -eq '\')) { $PolicyFolder += '\' }
$RolesDoc = Get-Content -delimiter "`n" -Path ($PolicyFolder + $AWSRolesFile) -ErrorAction SilentlyContinue
if (!$RolesDoc)
{
	Try
	{
		$RolesDoc = Get-Content -delimiter "`n" -Path $AWSRolesFile -ErrorVariable Err1 -ErrorAction Stop
	}
	Catch
	{
		write-warning "Unable to read '$($PolicyFolder + $AWSRolesFile)' `n$($Err1.Message)"
		return;
	}
}


# // Strip out any comments
$PolicyTxt = ''
foreach ($line in $RolesDoc)
{
	$line = $line.Replace('//','\\')		# Interchangable comments either // or \\
	if ($line.IndexOf('\\') -ge 0)
		{ 
			$LineSubset = "$($line.SubString(0,$line.IndexOf('\\')))`n"
			if ($LineSubset.Trim().Length -gt 0) { $PolicyTxt += $LineSubset }
		}
	else
		{ $PolicyTxt += "$line`n" }
}

$RoleDefinitions = @() 
$r1 = New-Object -Type RoleDefinition
$r1.RoleName = '*** DO NOT CREATE ***'
$r1.RoleType = '-'
$r1.Scope = '-'
# Add a blank definition to allow exit
$RoleDefinitions += $r1

# Convert to an object & check json syntax & length
$RoleDefinitions += ($PolicyTxt.Trim() | ConvertFrom-Json -ErrorAction Stop)		
if (!$RoleDefinitions)
{
	write-warning "Error in role definitions '$AWSRolesFile'!"
	Return
}

#
# Ask user to choose which role definitions to apply
$SelectedRoles = @($RoleDefinitions `
	| Select-Object -Property RoleName,Description,RoleType,Path,MaxSessionDuration `
	| Sort-Object -Property RoleType,RoleName `
	| Out-GridView -Title "Choose Roles to define:" -PassThru)
$SelectedRoles = @($RoleDefinitions | Where-Object { $SelectedRoles.RoleName -Contains $_.RoleName})
# TO DO - CHECK THIS!!! 
if ($SelectedRoles.Count -eq 0 -Or $SelectedRoles[0].Scope -like '-')
{
	write-host -ForegroundColor Yellow "No roles will be defined."
	$SelectedRoles = @()	# Ensure we don't go through list if user selected not to
}

Write-Progress -Activity $Activity -PercentComplete 100 -Completed 


# +-----------------------------------------------------------------------------+
# |  Process each AWS account													|
# +-----------------------------------------------------------------------------+
$ctr = [int32] 0
$Activity = "Apply policies to Account $AWSAccountID"
foreach ($AWSAccount in $AWSAccounts)
{
	$pctComplete = [string] ([math]::Truncate((++$ctr / $AWSAccounts.Count)*100))
	
	# Ensure Account number is exactly 12 digits (recheck)
	$AWSAccountId = $AWSAccount.AccountNumber
	$AWSAccountId = ([Int64]$AWSAccountId).ToString('000000000000')
	write-host -ForegroundColor Cyan "`n`n===================================="
	write-host -ForegroundColor Cyan "===== AWS Account $AWSAccountId ====="
	write-host -ForegroundColor Cyan "===================================="
	if ($AWSAccountId.Length -ne 12)
		{ write-warning "Invalid AWS Account '$AWSAccountId' in '$AWSAccountsCSV'"	}

	# Prepare for sts:AssumeRole
#	$AWSAccountId = "214667173281"   # DEBUG
	$RoleARN = 'arn:aws:iam::' + $AWSAccountId + ':role/CloudBootstrap'
	Write-Verbose "Assuming role '$RoleArn'"
	Try
	{
		Remove-Variable Err1
		$Result = Use-STSRole -RoleArn $RoleArn -ExternalId $ExternalId -RoleSessionName "BootstrapSession" `
					-Verbose -ErrorVariable Err1 -ErrorAction Stop
		$Creds = $Result.Credentials
		# $Creds is an object that now contains the AccessKeyId, SecretAccessKey, and SessionToken elements that you need in the following steps.
		# Use the -Credentials $Creds in the PowerShell cmdlets: get-iamroles -Credential $Creds
	}
	Catch
	{
		write-warning "sts:AssumeRole Failed:`n$($Err1.Message)"
		continue;	
	}

	# +---------------------------------------------+
	# | Apply each Policy Definition				|
	# +---------------------------------------------+
	foreach ($Policy in $PolicyDefinitions)
	{
		# Determine the policy name (based on the input file name; case is preserved)
		$PolicyName = $Policy.PolicyName

		# Progress bar...
		$Status1 = "Applying Policy '$PolicyName' - $pctComplete% Complete  ($ctr of $($AWSAccounts.Count))"
		Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1	
		
		# Retrieve existing policy (if any)
		$ExistingPolicy = Get-IAMPolicyList -Credential $Creds | Where-Object {$_.PolicyName -like $PolicyName}
		$PolicyDocument = $Policy.PolicyDocument	# Select the Policy Document in text format
		# Substitute any %%AccountID%% or <ACCOUNT_NUMBER> in the policy definition
		$PolicyDocument = $PolicyDocument.Replace('%%AccountID%%', $AWSAccountID).Replace('<ACCOUNT_NUMBER>',$AWSAccountID)

		if ($ExistingPolicy)
		{
			# Delete oldest version if there are already 5 versions
			# TODO: Delete the second oldest policy if the oldest is the default
			$PolicyList = @(Get-IAMPolicyVersionList -PolicyArn $ExistingPolicy.Arn -Credential $Creds | Sort-Object -Property CreateDate -Descending)
			if ($PolicyList[4])
			{
				if (!$PolicyList[4].IsDefaultVersion)
				{
					write-verbose "Removing oldest policy version from $($ExistingPolicy.Arn)"
					$x = Remove-IamPolicyVersion -PolicyArn $ExistingPolicy.Arn -Credential $Creds -VersionId $PolicyList[4].VersionId -Force
				}
				else
					{ write-warning "The oldest policy version found appears to be the default version and cannot be removed by this script." ; Return; }
			}
			
			# Update the Policy Version if the policy itself already exists
			write-host -ForegroundColor Yellow "Updating existing policy '$PolicyName' (Length: $($Policy.PolicyLength) / $($PolicyDocument.Length)) in $AWSAccountId" 
			write-verbose "Updating Policy '$PolicyName': `n$PolicyDocument"
			Try
			{
				$Err1 = $null
				$x = New-IamPolicyVersion -PolicyArn $ExistingPolicy.Arn `
						-PolicyDocument $PolicyDocument -SetAsDefault $true -Force -Credential $Creds `
						-ErrorAction Stop -ErrorVariable Err1
			}
			Catch
			{
				write-warning $err1[0].Message
				write-host -ForegroundColor Yellow "`n==== POLICY DOCUMENT ===="
				write-host $PolicyDocument
				write-warning "Unable to create policy:`n$PolicyDocument"
				Return
			}

				
			# Update the Policy Description
			# TODO!!!!!!!!!!!!!!
					}
		else
		{
			# Define the new policy
			write-host -ForegroundColor Yellow "`nCreating new policy '$PolicyName' (Length: $($Policy.PolicyLength)) in $AWSAccountId" 
#			write-verbose "Creating Policy '$PolicyName':`n$($Policy.Description)`n$PolicyDocument" 
			Try
			{
				$x = New-IamPolicy -PolicyName $PolicyName -PolicyDocument $PolicyDocument `
							-Description $Policy.Description -Force -Credential $Creds `
							-ErrorVariable Err1 -ErrorAction Stop # -Force
			}
			Catch
			{
				write-warning $err1[0].Message
				write-host -ForegroundColor Yellow "`n==== POLICY DOCUMENT ===="
				write-host $PolicyDocument
				write-warning "Unable to create policy:`n$PolicyDocument"
				Return
			}
		}
	} # foreach $policy
	
	
	# +---------------------------------------------+
	# |  Get SAML Providers for the account			|
	# |  If default doesn't exist, then add it!		|
	# +---------------------------------------------+
	$SAMLProviders = @(get-IAMSAMLProviderList -Credential $Creds)
	$SAMLProviderARN = $SAMLProviderDefault.Replace('%%AccountID%%', $AWSAccountID)
	if ($SAMLProviders.Arn -Contains ($SAMLProviderARN))
	{
		$AssumeRolePolicyDocument = $AssumeRolePolicyDocumentTemplate.Replace('%SAMLProviderARN%', $SAMLProviderARN)
		$AssumeRolePolicyDocumentEncoded = [system.web.httputility]::UrlEncode($AssumeRolePolicyDocument)
	}
	else
	{
		# NOTE: This script does not set or update the SAML Identity Provider in AWS. 
		# If this were to change, this is the place to do it here.
		write-warning "Default SAML provider not found in account $AWSAccountId. Trust relationship MUST be created for $SAMLProviderARN."
		write-output "See IAM > Identity Providers"
		# TBD - TODO - Set up trust relationship to $SAMLProviderARN
		write-warning "NOT IMPLEMENTED - Creation of SAML trust relationship. Please do this by hand" 
	}

	# +---------------------------------------------+
	# |  Prepare to apply role definitions			|
	# +---------------------------------------------+
	# Roles utilize the account's role name prefix.
	# We can find this via ACtive Directory and/or in the CSV file.
	# Extract the Role Name Prefix (that part used in the AD group name)
	$RoleNamePrefix = $AWSAccount.RoleNamePrefix
	Try
	{
		$RoleNamePrefixAD = @(Get-AdGroup -ResultSetSize $null -ResultPageSize 5000 -Filter "SamAccountName -like 'g-PR-AWS-$AWSAccountId-*-CloudAdmin'" -ErrorAction SilentlyContinue)[0].Name 
	}
	Catch
	{
		$RoleNamePrefixAD = $Null
	}
	if ($RoleNamePrefixAD -And !$useCSVnameprefix)
		{ $RoleNamePrefixAD = $RoleNamePrefixAD.SubString(0,$RoleNamePrefixAD.Length -  11)}
	else
	{
		# Use the RoleName Prefix from the CSV
		$RoleNamePrefixAD = $AWSAccount.RoleNamePrefix
	}


	# Get the list of currently defined roles
	$CurrentRoles = @(Get-IamRoleList -Credential $creds)
	for ($i = 0; $i -lt $CurrentRoles.Count; $i++)
	{
		$CurrentRoles[$i] | Add-Member -NotePropertyName 'AssumeRolePolicyTxt' -NotePropertyValue $([System.Web.HttpUtility]::UrlDecode($CurrentRoles[$i].AssumeRolePolicyDocument))
		$AttachedPolicies = Get-IamAttachedRolePolicyList -RoleName $CurrentRoles[$i].RoleName -Credential $Creds
		$CurrentRoles[$i] | Add-Member -NotePropertyName 'AttachedPolicies' -NotePropertyValue $($AttachedPolicies | ConvertTo-json -Compress)
	}
	# DEBUG
#	$CurrentRoles | Select-Object -Property RoleName,Path,RoleId,MaxSessionDuration,Description,PermissionBoundary,CreateDate,AttachedPolicies,AssumeRolePolicyTxt,Arn,Tags | Out-GridView -Title "Roles for account $AWSAccountID"
	# [System.Web.HttpUtility]::UrlDecode($CurrentRoles[0].AssumeRolePolicyDocument)
	

	# +---------------------------------------------+
	# | Apply each Role Definition					|
	# +---------------------------------------------+
	foreach ($role in $SelectedRoles)
	{
		# Determine the proposed role name and Description
		$ProposedRoleName = $role.FullRoleName.Replace('%%RoleNamePrefix%%',$RoleNamePrefixAD.Replace("g-PR-AWS-$AWSAccountID-",''))
		$RoleDescription = ValidDescription -Description $role.Description -Title "Role '$ProposedRoleName'"

		# Progress bar...
		$Status1 = "Defining Role '$ProposedRoleName' - $pctComplete% Complete  ($ctr of $($AWSAccounts.Count))"
		Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1
		write-host -ForegroundColor Cyan "`n==== Role: $ProposedRoleName ===="
		
		# Do Substitutions on %%AccountID%%
		$TargetPolicies = @()
		foreach ($policy in $role.AttachedPolicies)
		{
			$Policy1 = ($policy | ConvertTo-Json | ConvertFrom-Json)
			$Policy1.PolicyArn = $Policy1.PolicyArn.Replace('%%AccountID%%', $AWSAccountID)
			$TargetPolicies += $policy1
		}
		
		if ($role.ADGroupUK)
		{
			# Determine Active Directory Group Name (with substitutions)
			$ADGroupName = $role.ADGroupUK.Name.Replace('%%AccountID%%',$AWSAccountID).Replace('%%RoleNamePrefix%%', $RoleNamePrefixAD.Replace("g-PR-AWS-$AWSAccountID-",''))
			write-verbose "Checking AD for existing group name: '$ADGroupName'"
			if ($ADGroupName.Length -gt 64) { write-warning "The AD Group Name '$ADGroupName' is longer than 64 characters!"	 }
			Try
			{
				$ADGroup = Get-ADGroup -filter "SamAccountName -like '$ADGroupName'" -ErrorAction Stop
			}
			Catch
			{
				$ADGroup = $null
			}
			if ($ADGroup)
				{ write-output "  The associated AD Group '$ADGroupName' exists." }
			else
			{	
				# Create the AD Group in the OU
				# This MUST be done in the context of PRV account!! PowerShell defaults to desktop account.
				# https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-adgroup
				# https://social.microsoft.com/Forums/en-US/10e33f33-ff43-4bb7-8ac7-4c598fb039cf/creating-an-ad-group-with-the-quotnotesquot-field-populated-powershell-calls-it-info?forum=Offtopic
				if ($PRVcredentialAsk -eq $false)
				{
					write-host -ForegroundColor Yellow "AD Group creation is required."
					write-host -ForegroundColor Yellow -NoNewLine "Enter your PRV credentials for the target domain via the popup: "
					$PRVcredential = Get-Credential -Username "PRV-xxxxx" -Message "Enter PRV account credentials"
					write-host ""
					$PRVcredentialAsk = $true
					if (!$PRVcredential)
						{ write-warning "Without account credentials, you will be unable to create new AD groups." }
				}
				if ($PRVcredential)
				{
					write-host -ForegroundColor Yellow "  Creating AD Group: $ADGroupName"
					write-host "    OU: '$($role.ADGroupUK.OU)' `n    Managed by '$($role.ADGroupUK.ManagedBy)'..."
					if ($ADGroupName.Length -gt 64) { write-Warning "AD Group name exceeds 64 characters and will be truncated." }
					$Notes = $role.ADGroupUK.Notes.Replace('`n',"`r`n")	    # Substitute <cr><lf>
					
					# Create the AD Group
					Try
					{
						$g = New-ADGroup -Name $ADGroupName -SamAccountName $ADGroupName `
								-GroupCategory Security -GroupScope Global -DisplayName $ADGroupName `
								-Path $role.ADGroupUK.OU -Description $RoleDescription `
								-Credential $PRVcredential `
								-OtherAttributes @{info=$Notes} `
								-ManagedBy $role.ADGroupUK.ManagedBy -PassThru `
								-ErrorAction Stop
						
						# Add members
					}
					Catch
					{
						write-warning "ERROR: New Group Creation failed:"
						write-output $Err1[0].Message
					}
					
					# Add the members to the group automatically  ************ TODO ****************
					# The members may be a Username, UPN, or an AD/AAD group name
					# If no match is found, just output a Warning and continue with the next member
					foreach ($member in $role.ADGroupUK.Members)
					{
						# See if it is a group
						$memberObj = @(Get-AdGroup -ResultSetSize $null -ResultPageSize 100 -Credential $PRVcredential -Filter "SamAccountName -like '$member'" -ErrorAction SilentlyContinue)
						if (!$memberObj)
							{ $memberObj = @(Get-AdUser -ResultSetSize $null -ResultPageSize 100 -Credential $PRVcredential -Filter "SamAccountName -like '$member'" -ErrorAction SilentlyContinue) }
						if (!$memberObj)
							{ $memberObj = @(Get-AdUser -ResultSetSize $null -ResultPageSize 100 -Credential $PRVcredential -Filter "UserPrincipalName -like '$member'" -ErrorAction SilentlyContinue) }
						if ($memberObj)
						{
							# Add the user/group to the new AD group
							write-output "    Adding '$member' to AD group '$ADGroupName'..."
							Add-AdGroupMember -Identity $ADGroupName -Members $member -Credential $PRVcredential
						}
						else
							{ write-Warning "Unable to find AD user or group matching '$member'" }
					}
					# $MList = $role.ADGroupUK.Members -join '; '
					# write-host "    Default (initial) Members: $MList"
					# if ($MList.Length -gt 1)
					# 	{ write-warning "*** At this time, the default members (as listed above) are NOT added automatically! Please add them. ***" }
				}
				else
				{
					write-host "  The associated AD Group '$ADGroupName' does not exist and cannot be created at this time."
				}
				
				# TEST
	#			$ADGroupName	= 'g-Developer'
	#			$ADGroupOU_UK			= 'OU=AWSRoles,OU=CloudServices,OU=Groups,DC=uk,DC=COMPANY,DC=com'
	#			$RoleDescription		= 'Test'
	#			New-ADGroup -Name $ADGroupName -SamAccountName $ADGroupName `
	#					-GroupCategory Security -GroupScope Global -DisplayName $ADGroupName `
	#					-Path $ADGroupOU_UK -Description $RoleDescription `
	#					-ManagedBy 'USERNAME'
						
				# Next, tick the box "Manager can update membership list"
				# SEE: http://vcloud-lab.com/entries/active-directory/powershell-active-directory-adgroup-managedby-checkbox-manager-can-update-membership-list
				# TODO!!!  TBD
						
				# Save info for later output
				if (!$g)
				{
					$ADGroup = New-Object ADGroup
					$ADGroup.Name = $ADGroupName
					$ADGroup.Description = $RoleDescription
					$ADGroups += $ADGroup
				}
			}
		}
		
		# If the role already exists, then warn the user as we cannot update existing roles YET
		if ($CurrentRoles.RoleName -Contains $ProposedRoleName)
		{
			write-output "  The role '$ProposedRoleName' already exists in AWS account $AWSAccountId. Only the policy assignments will be updated."
			
			# Determine the set of attached policies on the existing role
			# https://docs.aws.amazon.com/powershell/latest/reference/items/Get-IAMAttachedRolePolicyList.html
			$CurrentAttachedPolicies = Get-IAMAttachedRolePolicyList -RoleName $ProposedRoleName -MaxItem 100 -Credential $Creds
			# $CurrentAttachedPolicies = Get-IAMAttachedRolePolicyList -RoleName devtest-DL-CBS-SecurityAdmin -Credential $Creds 
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
		else
		{
			# Create the role
			# https://docs.aws.amazon.com/powershell/latest/reference/items/New-IAMRole.html
			write-host -ForegroundColor Yellow "  Creating new role '$ProposedRoleName' in AWS account $AWSAccountId"
			$r = New-IamRole -RoleName $ProposedRoleName -Description $RoleDescription -MaxSessionDuration $role.MaxSessionDuration `
                            -AssumeRolePolicyDocument $AssumeRolePolicyDocument.Replace('%%AccountID%%', $AWSAccountId) `
							-PermissionsBoundary $null -Credential $Creds -ErrorAction Stop  # -Tag  $AssumeRolePolicyDocumentEncoded
			
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
			
			# Check if AD Group exists...

			# Attach the Tags
			# TBD  Add-IamRoleTag
		}
	}
	
} # foreach $AWSAccount
Write-Progress -Activity $Activity -PercentComplete 100 -Completed

# Output any action items
if ($ADGroups)
{
	write-output "`n====================================================`nPlease create the following Active Directory Groups:`n===================================================="
	write-output "ServiceNow URL for Request: TBD"
	$ADGroups | Fl
	write-output $MoreInformation	
}


write-host "Done!`n"

