# AWS Policies and Roles
This folder contains the definitions for Amazon Web Service (AWS) RBAC policies and roles.

Most 'people' roles definitions are standardized across all AWS accounts.
This ensures consistency in the rights and permissions granted by each role.
For example, a 'CloudNetworkAdmin' has exactly the same set of rights in each AWS account.

## One-Off Definitions
Where a special permission is required for a particular individual or team, an appropriately named policy
is created for that individual (or group) and then linked to either an existing role or a new role.
The policy definition should ONLY grant the additional rights and SHOULD NOT clone an existing standard definition.

For example, if a 'Cloud Developer' requires access to a new service which is normally blocked,
then a separate policy definition may be created for that service and then linked to a new or existing role.
Alternatievly (recommended approach) is to use an existing built-in policy and link it to the existing role.
This makes it clear what the additional rights are for the role.

If there are multiple requests for the same rights, it may be time to incorporate the right into one
of the standard Cloud policy definitions.  A balanced risk-based approach should be used when making
this decision (i.e., balances the risk of the additional right vs. managing one-offs).

## JSON Format
Each role is defined in a seperate JSON document, typically named with the role name.
The role definition follows the AWS format BUT also may contain additional properties
(such as PolicyName and PolicyDescription) and may also contain embedded comments
and in some cases, may have embedded substitutions such as "<ACCOUNT_NUMBER>" or "%%ACCOUNT_ID%%".
These handled by the **Set-AwsRole.ps1** script. 

Comments may be inserted using '//' or '\\\\'. The double slashes and anything after it on each line is
stripped by the associated tools before the JSON is converted into an object.

NOTE: If a policy is to be applied by hand, it will be necessary to remove any comments and ensure
that all ACCOUNT_NUMBER fields are properly filled in.

An example AWS policy definition:
<pre>
// CloudSampleRole
// Grants full access to IAM, CloudWatch, CloudWatch Events, CloudWatch Logs, CloudTrail, and Simple Notification Service (SNS).
//
{
    "PolicyName": "CloudSampleRole",       // Non-Standard Property
    "Description": "This is the description for the role which will be applied when the role is created.",   // Non-Standard Property
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudBootstrap20190928",
            "Effect": "Allow",
            "Action": [
                  "events:*",
                "cloudtrail:*",
                "cloudwatch:*",
                "sns:*",
                "logs:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudBootstrapIAM20191023",
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": [
                "arn:aws:iam::*:saml-provider/*",
                "arn:aws:iam::*:policy/*",
                "arn:aws:iam::*:oidc-provider/*",
                "arn:aws:iam::*:instance-profile/*",
                "arn:aws:iam::*:user/*",
                "arn:aws:iam::*:role/*",
                "arn:aws:iam::*:server-certificate/*",
                "arn:aws:iam::*:sms-mfa/*",
                "arn:aws:iam::*:access-report/*",
                "arn:aws:iam::*:group/*",
                "arn:aws:iam::*:mfa/*/*"
            ]
        }
    ]
}
</pre>

**NOTE:** Since the JSON file contains non-standard properties and comments, it cannot be
directly cut and pasted into the AWS portal as a definition. You must manually remove the non-standard
properties and comments in this case.

### SIDs
Each effect block within the json documant may have a __"SID":__ statement.
This should be descriptive of the purpose of the block.
It also should contain the last modification date of the block in YYYYMMDD format, as shown in the example above.
SIDs may only contain letters and numbers and may not contain spaces or any symbols such as dashes and underscores.

## Developer Guidance
See the **GUIDANCE.md** for information on creating custom RBAC policy, roles, and user accounts.

