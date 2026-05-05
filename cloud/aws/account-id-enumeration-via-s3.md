# Account ID Enumeration via S3

### Overview

**IAM Roles** are temporary identities in AWS. Unlike IAM Users which carry permanent credentials, roles are assumed on demand and issue short-lived credentials via STS (Security Token Service). Every role has two policy components:

* **Trust Policy** -- defines who can assume the role
* **Permission Policy** -- defines what the role can do once assumed

**IAM Policy Condition Keys** are constraints you can attach to a policy statement. Instead of just allowing `s3:GetObject` on a bucket, you can allow it only if the bucket belongs to a specific AWS account. The condition key for this is `s3:ResourceAccount`. Example:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": "arn:aws:s3:::*",
  "Condition": {
    "StringLike": {
      "s3:ResourceAccount": "1*"
    }
  }
}
```

**S3 bucket names are globally unique and globally resolvable.** Any bucket with a known name is reachable at `https://<bucket-name>.s3.amazonaws.com`. Bucket names get leaked all the time from page source, JavaScript files, API responses, and DNS records.

These three facts are the foundation of the attack.

### Scenario

During an external assessment of a target company, browsing to their public-facing website reveals that product images are loaded directly from an S3 bucket. Checking the page source:

```html
<img src="https://vault-tech-assets.s3.amazonaws.com/images/hero.png">
```

Bucket name: `vault-tech-assets`.

If we browse the bucket URL it will confirm if it is publicly accessible. Most of the time public S3 buckets only contain non-sensitive static assets. But the bucket name is already useful.

### Account ID

An AWS account ID is a 12-digit number. It is not a credential and does not grant access on its own. However, it is a pivot point for further enumeration:

* Public EBS snapshots are scoped by account ID and region. Any AWS user in the same region can query and mount them.
* Public RDS snapshots work the same way.
* Knowing the account ID narrows your target surface significantly during a cloud assessment.

The goal is to resolve the account ID from just a bucket name.

### Core Technique

AWS evaluates IAM policy conditions server-side. When you make an S3 request using a role that has a `s3:ResourceAccount` condition, AWS checks whether the bucket's actual owner account matches the condition before allowing or denying the request.

This evaluation is binary: the request either succeeds or fails. That binary response is the reason why this technique is possible.

By setting up a role in your own AWS account with a `StringLike` condition using a wildcard, you can test one digit at a time:

* Try `s3:ResourceAccount: "1*"` -- does the request succeed? Yes, the account ID starts with 1.
* Try `s3:ResourceAccount: "10*"` -- denied. Move to the next digit.
* Try `s3:ResourceAccount: "11*"` -- denied. Keep going.
* Try `s3:ResourceAccount: "12*"` -- succeeds. Account ID starts with 12.

Repeat until all 12 digits are confirmed. The full enumeration takes roughly 120 requests instead of a trillion.

**This runs entirely in your own AWS account.** You are abusing AWS's own policy evaluation engine. The target's account sees nothing.

### Exploitation

We can set up an offensive role in our AWS account with the following permission policy attached:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

Then we need to configure IAM user credentials that have permission to assume this role via AWS-CLI:

```bash
aws configure --profile pwned
```

After configuring the profile we can use `s3-account-search` against the target bucket, passing in role ARN as the offensive infrastructure:

```bash
AWS_PROFILE=pwned s3-account-search arn:aws:iam::391827465012:role/recon-role vault-tech-assets
```

Output:

```
Starting search (using account ID from role)
Found: 3
Found: 39
Found: 391
<SNIP>
Found account ID: 394820176523
```

### Extending the Recon

With the account ID in hand, the next step is identifying the region. Public EBS and RDS snapshots are only visible to users in the same region they were created in, so region matters.

A simple cURL request can be used to leak this:

```bash
curl -I https://vault-tech-assets.s3.amazonaws.com
```

Now we can look for the response header containing the region:

```
x-amz-bucket-region: us-east-1
```

Now we can query for public EBS snapshots owned by this account in that region:

```bash
aws ec2 describe-snapshots --region us-east-1 --owner-ids 394820176523 --filters Name=snapshot-id,Values=snap-* --query 'Snapshots[?State==`completed`]'
```

A publicly exposed snapshot can contain credentials, config files, database dumps, or anything else that was on the volume at the time it was taken. It can open the door to further exposure of data and in worse cases even a breach is possible.

### Detection

From the defender's side, this attack is largely invisible. The STS `AssumeRole` calls and S3 condition evaluations all happen in the attacker's account. The target's CloudTrail logs nothing by default.

The only way to catch this is enabling **S3 data events**, which logs all `GetObject` and `ListBucket` calls including denied ones. These are not enabled by default and come at additional cost. Even then, what you would see is a series of access denied responses from an unknown external principal which is easy to miss without specific alerting.

From a hardening perspective, the root issue is the bucket being publicly accessible at all. If there is no business requirement for public access, S3 Block Public Access should be enforced at the account level. That does not prevent account ID enumeration from a known bucket name, but it eliminates the initial access path that usually follows.

### Resources

_Tool:_ [_s3-account-search_](https://github.com/WeAreCloudar/s3-account-search) _Research:_ [_Ben Bridts S3 Account ID Enumeration_](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/)
