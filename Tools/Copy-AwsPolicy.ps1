#Requires -Version 5
<#
.SYNOPSIS
	Copy-AwsPolicy: Copies one or more policy definitions from one AWS account to another.
.DESCRIPTION
	This script takes policy definitions as input files and then applies
	those definitions to selected AWS accounts. The input files may have
	embedded comments (which are stripped before the policy is applied).
	The comments are used to create the policy description.
	
	The list of accounts may be in 'AWS_Accounts.csv' in the current directory
	with the 1st line as 'AccountNumber,AccountName,RoleNamePrefix,Owner'.
	
	The remote AWS accounts must have a role 'CloudBootstrapper' with
	a trust relationship to the AWS user account in which this script is run.
	
.PARAMETER Rename
	By default, the prefix of policy names are renamed if they match the general
	naming convention for the source subscription (as based in the AWS acocunt CSV).
	For example, "PreProd-xyz" will be renamed to "Prod-xyz" if the target is a production account.
	This feature is a bit haphazzard and here as a convenience.  The bets practice is to keep the
	policy names consistent across environments.
	
.PARAMETER LocalGitRepo
	Specifies the path to the local synchronize git repository for Cloud Roles.

.NOTES
	Author: Lester Waters
	Version: v0.15
	Date: 13-Jul-21
	
.LINK

#>

# +=================================================================================================+
# |  PARAMETERS																						|
# +=================================================================================================+
[cmdletbinding()]   #  Add -Verbose support; use: [cmdletbinding(SupportsShouldProcess=$True)] to add WhatIf support
Param 
(
	[Parameter(Mandatory=$false)] [switch] $Rename				= $true,	# If true, policy is renamed where prefix matches
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

Class	PolicyDefinition
{
	[string]	$PolicyName
	[string]	$Description
	[string]	$PolicyDocument
	[int32]		$PolicyLength
	[PSObject]	$PolicyJSON
	[string]	$PolicyJSONtext
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
# Set-AWSCredential -AccessKey XXXXXXXXXXXXXXXX -SecretKey xxxxxxxxxxxxxxxxxxxxx -StoreAs Bootstrapper
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
# $SrcAWSAccountId = '214667173281'
$RoleARN = 'arn:aws:iam::' + $SrcAWSAccountId + ':role/CloudBootstrap'
Write-Verbose "Assuming role '$RoleArn'"
$Result = Use-STSRole -RoleArn $RoleArn -ExternalId $ExternalId -RoleSessionName "BootstrapSession" -Verbose 
$Creds = $Result.Credentials
# $Creds is an object that now contains the AccessKeyId, SecretAccessKey, and SessionToken elements that you need in the following steps.
# Use the -Credentials $Creds in the PowerShell cmdlets: get-iamroles -Credential $Creds


# +---------------------------------------------+
# | Retrieve all Custom Policy Definitions		|
# | and prompt for selection					|
# +---------------------------------------------+
$PolicyDefinitions = @()
$ExistingPolicies = Get-IAMPolicyList -Credential $Creds -Scope 'Local'
$ChosenPolicies = ($ExistingPolicies | Sort-Object -Property PolicyName `
						| Select-Object -Property PolicyName,Description,Path,UpdateDate,Arn,PolicyId `
						| Out-GridView -Title "Choose policy(s) to copy..." -PassThru)
if ($ChosenPolicies.Count -eq 0)
{
	write-host "No policies chosen!"
	return
}
foreach ($policy in $ChosenPolicies)
{
	# $PolicyIndex 	= $ExistingPolicy.PolicyId.IndexOf($policy.PolicyId)
	
	# Fetch description
	$Description	= $policy.Description
	if ($Description.Length -lt 3)
	{
		$Description = "Replication of $($policy.PolicyName) from account $SrcAWSAccountId"
	}
	
	# Fetch Policy Document as a string
	# and substitute out any account numbers matching source account
	$PolicyList = @(Get-IAMPolicyVersionList -PolicyArn $Policy.Arn -Credential $Creds | Where-Object {$_.IsDefaultVersion -eq $true})
	$VersionId = $PolicyList[0].VersionId
	$PolicyDocument			= [System.Web.HttpUtility]::UrlDecode((Get-IAMPolicyVersion -PolicyArn $Policy.Arn -VersionId $VersionId -Credential $Creds).Document)
	if ($PolicyDocument.Length -eq 0)
	{
		write-warning "Policy Document for $($policy.PolicyName) from account $SrcAWSAccountId is EMPTY!"
		return
	}
	# $PolicyDocument		= ($ExistingPolicies[$PolicyIndex].PolicyDocument).Replace($SrcAWSAccountId, '%%AccountID%%')
	
	# Create Object
	$Entry = New-Object PolicyDefinition
	$Entry.PolicyName		= $policy.PolicyName
	$Entry.Description		= $Description
	$Entry.PolicyDocument	= $PolicyDocument.Replace($SrcAWSAccountId, '%%AccountID%%')	# Pull out any source account references
	$PolicyDefinitions += $Entry
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
# |  Process each AWS account													|
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
	# | Apply each Policy Definition				|
	# +---------------------------------------------+
	foreach ($Policy in $PolicyDefinitions)
	{
		# Determine the policy name (based on the input file name; case is preserved)
		$PolicyName = $Policy.PolicyName

		# Fetch Name and substitute prefix (if any)
		$SourcePrefix	= $AWSSourceAccounts[0].RoleNamePrefix.Split('-')[0]
		$DestPrefix		= $AWSAccount.RoleNamePrefix.Split('-')[0]
		if ($Rename -And $PolicyName -like "$SourcePrefix*")
		{
			# Substitute if matched
			$PolicyName1 = $DestPrefix + $PolicyName.SubString($SourcePrefix.Length) 
			# write-host "SOURCE PREFIX: $SourcePrefix;   DEST PREFIX: $DestPrefix"
			write-host "CURRENT POLICY NAME: $PolicyName    PROPOSED NAME: $PolicyName1"
			$PolicyName = $PolicyName1
		}
	
		# Progress bar...
		$Status1 = "Applying Policy '$PolicyName' - $pctComplete% Complete  ($ctr of $($AWSTargetAccounts.Count))"
		Write-Progress -Activity $Activity -PercentComplete $pctComplete -Status $Status1	
		write-host -ForegroundColor Cyan "  Policy: $PolicyName"
		
		# Retrieve existing policy (if any)
		$ExistingPolicy = Get-IAMPolicyList -Credential $Creds | Where-Object {$_.PolicyName -like $PolicyName}
		$PolicyDocument = $Policy.PolicyDocument	# Select the Policy Document in text format
		# Substitute any %%AccountID%% or <ACCOUNT_NUMBER> in the policy definition
		$PolicyDocument = $PolicyDocument.Replace('%%AccountID%%', $AWSAccountID).Replace('<ACCOUNT_NUMBER>',$AWSAccountID)

		if ($ExistingPolicy)
		{
			# Delete oldest version if there are already 5 versions
			$PolicyList = @(Get-IAMPolicyVersionList -PolicyArn $ExistingPolicy.Arn -Credential $Creds | Sort-Object -Property CreateDate -Descending)
			if ($PolicyList[4])
			{
				if (!$PolicyList[4].IsDefaultVersion)
				{
					write-verbose "Removing oldest policy version from $($ExistingPolicy.Arn)"
					$x = Remove-IamPolicyVersion -PolicyArn $ExistingPolicy.Arn -Credential $Creds -VersionId $PolicyList[4].VersionId -Force
				}
				else
					{ write-warning "Oldest policy version is the default and cannot be removed by this script." ; Return; }
			}
			
			# Update the Policy Version if the policy itself already exists
			write-host -ForegroundColor Yellow "Updating existing policy '$PolicyName' (Length: $($PolicyDocument.Length) / $($PolicyDocument.Length)) in $AWSAccountId" 
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
			write-host -ForegroundColor Yellow "`nCreating new policy '$PolicyName' (Length: $($PolicyDocument.Length)) in $AWSAccountId" 
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
	
} # foreach $AWSAccount
Write-Progress -Activity $Activity -PercentComplete 100 -Completed


write-host "Done!`n"

