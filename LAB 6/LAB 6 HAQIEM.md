# LAB 6: Object Storage Security & the Data Security Lifecycle
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Lecturer:** Ms. Adani  
**Student Name:** Muhammad Haqiem Bin Mohd Fauzi  
**Student ID:** 52215225398  
**Topic:** Bucket Exposure, Resource Policies, SSE-KMS, Versioning, Data Remanence, Lifecycle Policies, and Provable Cryptographic Erasure — Amazon S3 on LocalStack  

---

## Table of Contents
1. [Executive Summary & Curriculum Mapping](#1-executive-summary--curriculum-mapping)
   - [1.1 Executive Summary](#11-executive-summary)
   - [1.2 Course Learning Outcomes & CCSK v5 Mapping](#12-course-learning-outcomes--ccsk-v5-mapping)
   - [1.3 The Data Security Lifecycle Architecture](#13-the-data-security-lifecycle-architecture)
2. [Theoretical Foundations: Object Storage Security vs. Traditional Storage](#2-theoretical-foundations-object-storage-security-vs-traditional-storage)
   - [2.1 Flat Namespace Architecture vs. Hierarchical Filesystems](#21-flat-namespace-architecture-vs-hierarchical-filesystems)
   - [2.2 Dual Authorization Planes: IAM Identity vs. S3 Bucket Resource Policies](#22-dual-authorization-planes-iam-identity-vs-s3-bucket-resource-policies)
   - [2.3 Policy Evaluation Hierarchy: The Explicit Deny Invariant](#23-policy-evaluation-hierarchy-the-explicit-deny-invariant)
   - [2.4 Account-Level Preventative Guardrails vs. Detective Controls](#24-account-level-preventative-guardrails-vs-detective-controls)
   - [2.5 Object-Level Data Remanence & S3 Versioning Mechanics](#25-object-level-data-remanence--s3-versioning-mechanics)
   - [2.6 Cryptographic Erasure: Provable Deletion in Multi-Tenant Cloud](#26-cryptographic-erasure-provable-deletion-in-multi-tenant-cloud)
3. [Lab Environment Setup & Pre-Flight Verification](#3-lab-environment-setup--pre-flight-verification)
   - [3.1 LocalStack Initialization with IAM Enforcement](#31-localstack-initialization-with-iam-enforcement)
   - [3.2 AWS CLI Configuration & STS Identity Check](#32-aws-cli-configuration--sts-identity-check)
4. [Session A (Week 11): Object Storage & The Exposure Problem](#4-session-a-week-11-object-storage--the-exposure-problem)
   - [4.1 Task 1 — Classify the Data Before You Store It](#41-task-1--classify-the-data-before-you-store-it)
   - [4.2 Task 2 — Reproduce the Archetypal Cloud Breach](#42-task-2--reproduce-the-archetypal-cloud-breach)
   - [4.3 Task 3 — Remediate with Block Public Access & Least-Privilege Policies](#43-task-3--remediate-with-block-public-access--least-privilege-policies)
   - [4.4 Task 4 — Identity Policy vs. Resource Policy Authorization](#44-task-4--identity-policy-vs-resource-policy-authorization)
5. [Session B (Week 12): Protecting, Retaining, and Retiring Data](#5-session-b-week-12-protecting-retaining-and-retiring-data)
   - [5.1 Task 5 — Default Server-Side Encryption at Rest (SSE-KMS)](#51-task-5--default-server-side-encryption-at-rest-sse-kms)
   - [5.2 Task 6 — Delegated Access & The Condition-Key Trap](#52-task-6--delegated-access--the-condition-key-trap)
   - [5.3 Task 7 — Versioning, Delete Markers & Object-Level Data Remanence](#53-task-7--versioning-delete-markers--object-level-data-remanence)
   - [5.4 Task 8 — Automated Lifecycle Rules & Provable Cryptographic Erasure](#54-task-8--automated-lifecycle-rules--provable-cryptographic-erasure)
6. [Formal Lab Deliverables](#6-formal-lab-deliverables)
   - [6.1 Deliverable 1: Evidence Screenshots Matrix](#61-deliverable-1-evidence-screenshots-matrix)
   - [6.2 Deliverable 2: Completed Data Classification Table](#62-deliverable-2-completed-data-classification-table)
   - [6.3 Deliverable 3: Rigorous Short-Answer Solutions (Q1 – Q6)](#63-deliverable-3-rigorous-short-answer-solutions-q1--q6)
   - [6.4 Deliverable 4: Official Verification Command Output Block](#64-deliverable-4-official-verification-command-output-block)
7. [Security Best-Practices Checklist](#7-security-best-practices-checklist)
8. [Cleanup & Teardown Protocol](#8-cleanup--teardown-protocol)
9. [Advanced Expansion Considerations & Enterprise Hardening](#9-advanced-expansion-considerations--enterprise-hardening)
10. [References & Regulatory Standards](#10-references--regulatory-standards)

---

## 1. Executive Summary & Curriculum Mapping

### 1.1 Executive Summary
Cloud object storage (such as Amazon Simple Storage Service, S3) serves as the backbone of modern cloud applications, data lakes, and enterprise backup repositories. However, because object storage relies on web-native RESTful APIs and flat key namespaces rather than traditional POSIX filesystem boundaries, misconfigurations represent the single most common vector for catastrophic real-world cloud data breaches. 

This laboratory investigation explores the complete **Data Security Lifecycle** (Create $\rightarrow$ Store $\rightarrow$ Use $\rightarrow$ Share $\rightarrow$ Archive $\rightarrow$ Destroy) within an emulated Amazon S3 environment running on **LocalStack Pro**. The lab systematically implements defense-in-depth security controls across two distinct sessions:
- **Session A (Week 11): Data Classification, Exposure & Authorization:** We establish object sensitivity tagging, deliberately reproduce the archetypal open-bucket data breach via over-permissive resource policies (`Principal: "*"`), enforce preventative account-level guardrails using **S3 Block Public Access (BPA)**, implement least-privilege prefix scoping, and resolve authorization conflicts between **Identity-Based (IAM)** and **Resource-Based (Bucket)** policies.
- **Session B (Week 12): Cryptographic Protection, Controlled Sharing, Remanence & Erasure:** We enforce default server-side encryption with customer-managed KMS keys (**SSE-KMS**) and S3 Bucket Keys, issue time-bounded delegated access via **Presigned URLs**, diagnose transport security condition traps (`aws:SecureTransport`), demonstrate object-level **Data Remanence** through S3 Versioning and Delete Markers, automate retention through **S3 Lifecycle Rules**, and execute irreversible **Cryptographic Erasure**.

```
+=========================================================================================================+
|                                    CLOUD DATA SECURITY LIFECYCLE (S3 / KMS)                             |
+=========================================================================================================+
|                                                                                                         |
|   1. CREATE & CLASSIFY                2. STORE & PROTECT                 3. USE & AUTHORIZE             |
|   - Define Sensitivity Tiers          - S3 Block Public Access (BPA)     - IAM Policy (Identity)        |
|   - Apply Object Tags (S3 Tagging)    - SSE-KMS Customer-Managed Key     - Bucket Policy (Resource)     |
|   - Prefix: public/, internal/, conf/ - S3 Bucket Keys (Envelope Opt)    - Explicit Deny Precedence     |
|                                                                                                         |
|                      │                                  │                                  │            |
|                      ▼                                  ▼                                  ▼            |
|   +───────────────────────+          +───────────────────────+          +───────────────────────+       |
|   | Object Classification |  =====>  | Envelope Encryption   |  =====>  | Dual-Plane Evaluation |       |
|   | Tag: classification=* |          | aws:kms (AES-256 GCM) |          | Deny > Allow > DefDeny|       |
|   +───────────────────────+          +───────────────────────+          +───────────────────────+       |
|                                                                                                         |
|                      │                                  │                                  │            |
|                      ▼                                  ▼                                  ▼            |
|   4. SHARE SECURELY                   5. ARCHIVE & RETAIN                6. DESTROY (ERASURE)           |
|   - Time-Bounded Presigned URLs       - S3 Versioning & Delete Markers   - Delete All Version IDs       |
|   - HMAC-SHA256 Signature Auth        - S3 Lifecycle Automated Rules     - Disable & Schedule Key Del   |
|   - Ephemeral Access Delegation       - Noncurrent Version Expiration    - Cryptographic Shredding      |
|                                                                                                         |
+=========================================================================================================+
```

### 1.2 Course Learning Outcomes & CCSK v5 Mapping
- **Course Learning Outcome (CLO2):** Construct secure cloud operations that safeguard data confidentiality and integrity (**VBE3** — Integrity, **SC8** — Integrated Problem-Solving).
- **Lecture Alignment:**
  - **Week 4:** Data Protection (Encryption at Rest, Key Management, Envelope Encryption).
  - **Week 10:** Policy, Compliance & Risk (Access Control, Guardrails, Resource Policies).
  - **Week 11:** Compliance Assessment & Reporting (Audit Trails, Retention, Provable Deletion).
- **Cloud Security Alliance (CSA) CCSK v5 Alignment:**
  - **Domain 5 (Data Security):** Data Security Lifecycle, Storage Security, Encryption Key Management, Data Remanence, and Sanitization.
  - **Domain 4 (Organization Management):** Risk Management and Preventative Guardrails.
  - **Domain 9 (Application Security):** REST API Authorization and Resource-Based Policies.

---

## 2. Theoretical Foundations: Object Storage Security vs. Traditional Storage

### 2.1 Flat Namespace Architecture vs. Hierarchical Filesystems
In POSIX file systems (e.g., ext4, NTFS), directories are genuine physical index nodes (inodes) that establish kernel-enforced permission inheritance. If access to `/confidential` is blocked, nested files cannot be traversed.

Conversely, **Amazon S3 is a flat object store**. There are no directories, sub-directories, or folders. An object key such as `confidential/record.txt` is simply a single UTF-8 string containing a forward slash (`/`) delimiter. This architectural difference introduces significant security implications:
1. S3 bucket policies evaluate authorization based on **string prefix matching** (`arn:aws:s3:::bucket/prefix/*`).
2. A wildcard misconfiguration such as `Resource: "arn:aws:s3:::bucket/*"` exposes every object in the bucket simultaneously across all logical tiers.

```
POSIX Hierarchical Filesystem:
/ (Root)
└── [confidential] (Directory Inode - 0700) ───► record.txt (Inherits boundary)

S3 Flat Object Store:
Bucket: miit-patient-records-24535
├── Object Key: "public/notice.txt"
├── Object Key: "internal/roster.txt"
└── Object Key: "confidential/record.txt"  <── Flat string key; requires explicit prefix scoping!
```

### 2.2 Dual Authorization Planes: IAM Identity vs. S3 Bucket Resource Policies
Access evaluation in AWS S3 is governed simultaneously by two distinct policy domains:
1. **Identity-Based Policies (IAM Policies):** Attached directly to IAM Users, Roles, or Groups. They define what an identity is permitted to request (`"Action": ["s3:GetObject"]`, `"Resource": "*"`).
2. **Resource-Based Policies (S3 Bucket Policies):** Attached directly to the S3 bucket. They specify who (which Principal) can perform operations on the bucket and its objects.

```
       [ Requestor / IAM Identity ]              [ Amazon S3 Bucket ]
                    │                                      │
        (Attached: IAM Policy)                  (Attached: Bucket Policy)
                    │                                      │
                    └──────────────► [ AWS IAM ] ◄─────────┘
                                     Evaluation
                                       Engine
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
            [ EXPLICIT DENY ]                         [ EXPLICIT ALLOW ]
           (Immediate Override)                  (Requires at least 1 Allow)
```

### 2.3 Policy Evaluation Hierarchy: The Explicit Deny Invariant
When an IAM principal makes a request to an S3 resource within the same AWS account, the AWS Policy Evaluation Logic follows strict deterministic precedence:
$$\text{Decision} = \begin{cases} 
\mathbf{DENY} & \text{if any policy contains an Explicit Deny} \\
\mathbf{ALLOW} & \text{if at least one policy contains an Explicit Allow AND no Explicit Deny exists} \\
\mathbf{DENY} & \text{Default Deny (Implicit Deny if no Allow exists)}
\end{cases}$$

An **Explicit Deny** in either the IAM policy or the Bucket policy immediately halts evaluation and denies access, overriding all concurrent Allow statements.

### 2.4 Account-Level Preventative Guardrails vs. Detective Controls
- **Detective Controls:** (e.g., AWS Security Hub, AWS Config) inspect the environment retrospectively and generate an alert or ticket when a bucket is made public. While useful for auditing, detective controls create a "window of vulnerability" during which data can be exfiltrated.
- **Preventative Guardrails:** (e.g., S3 Block Public Access, Service Control Policies) act as an immutable gatekeeper at the API gateway layer. S3 Block Public Access enforces four discrete settings:
  1. `BlockPublicAcls`: Prevents new public ACLs from being uploaded.
  2. `IgnorePublicAcls`: Causes S3 to ignore all existing public ACLs.
  3. `BlockPublicPolicy`: Rejects any `PutBucketPolicy` call that would allow public access.
  4. `RestrictPublicBuckets`: Restricts public bucket access strictly to AWS services and authorized users.

### 2.5 Object-Level Data Remanence & S3 Versioning Mechanics
In standard unversioned buckets, executing `s3:DeleteObject` permanently removes the object reference and deallocates the underlying storage blocks.

However, when **S3 Versioning** is enabled:
1. A standard `s3:DeleteObject` operation does **NOT** erase data. Instead, S3 generates and appends a **Delete Marker** with a unique `VersionId` as the current, latest version of the key.
2. Standard `s3:GetObject` requests without a `version-id` receive an HTTP `404 NoSuchKey` error.
3. However, all prior object revisions remain physically intact in storage. Anyone with `s3:GetObjectVersion` permission can retrieve the complete unredacted data by specifying `--version-id <ID>`. This creates severe **Data Remanence** risks under privacy frameworks like GDPR and PDPA unless per-version deletion is executed.

```
                                S3 VERSIONING TIMELINE
========================================================================================
1. Initial Upload (v1)      2. Updated Upload (v2)      3. Delete Request (Soft Delete)
----------------------      ----------------------      -------------------------------
[Key: record.txt]           [Key: record.txt]           [Key: record.txt]
Version: null / ID_1        Version: ID_2 (Latest)      DeleteMarker: ID_3 (Latest)
Data: "Diagnosis: A"        Data: "Diagnosis: B"        ───► get-object returns 404!
                            Version: ID_1 (Previous)    Version: ID_2 (Retained!)
                            Data: "Diagnosis: A"        Version: ID_1 (Retained!)
========================================================================================
```

### 2.6 Cryptographic Erasure: Provable Deletion in Multi-Tenant Cloud
In multi-tenant public clouds, physical data media sanitization standards (such as NIST SP 800-88 Rev. 1 degaussing or physical destruction) are impossible because underlying physical drives are shared among thousands of customers.

**Cryptographic Erasure (Crypto-Shredding)** resolves this dilemma:
- Every object is encrypted at rest using an asymmetric/symmetric key managed in AWS Key Management Service (KMS).
- When the KMS Customer Master Key (CMK) is disabled or scheduled for deletion, the cryptographic master key material is permanently destroyed.
- Without the key, the stored ciphertext is mathematically indistinguishable from random white noise ($2^{256}$ computational complexity). This provides legally defensible, provable sanitization across all backups, replicas, and versioned copies simultaneously.

---

## 3. Lab Environment Setup & Pre-Flight Verification

### 3.1 LocalStack Initialization with IAM Enforcement
To ensure authentic policy evaluation, LocalStack was initialized with `ENFORCE_IAM=1`. This forces the local emulator to parse and evaluate AWS Identity and Access Management policies against the AWS security specification rather than defaulting to permissive bypass mode.

```bash
# Terminate existing instances and run clean LocalStack container
docker rm -f localstack 2>/dev/null
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

# Configure helper endpoint variable for AWS CLI v2
export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

### 3.2 AWS CLI Configuration & STS Identity Check
We verified connectivity to LocalStack's Security Token Service (STS) to confirm the caller identity and obtain the root account ID (`000000000000`).

```bash
# Verify STS Caller Identity
aws $EP sts get-caller-identity
```

```json
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

#### Evidence: Pre-Flight STS Caller Identity
![LocalStack Setup](./Lab6_Evidence/01_LocalStack_Setup.png)
*Figure 3.1: Terminal output confirming AWS STS caller identity and root account ARN (`arn:aws:iam::000000000000:root`) on LocalStack.*

---

## 4. Session A (Week 11): Object Storage & The Exposure Problem

### 4.1 Task 1 — Classify the Data Before You Store It

Security engineering begins with **data classification**. A unique bucket was generated for a hospital patient records management system:
```bash
export BUCKET=miit-patient-records-24535
aws $EP s3api create-bucket --bucket $BUCKET
```

Three files representing distinct data sensitivity tiers were created and uploaded with corresponding AWS S3 object tags:

```bash
# 1. Public tier
echo 'Ward visiting hours 10am-8pm' > public-notice.txt
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

# 2. Internal tier
echo 'Staff duty schedule, week 12' > internal-roster.txt
aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

# 3. Confidential tier (Protected Health Information - PHI)
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'
```

#### Verification & Tag Inspection
```bash
# List all objects in table format
aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].{Key:Key,Size:Size}' --output table

# Verify classification tag on the confidential record
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

#### Evidence: Task 1 Object Ingestion & Classification Tagging
![Task 1 Upload and Tags](./Lab6_Evidence/02_Task1_Upload_Tags.png)
*Figure 4.1: S3 object table listing showing all three objects (`public/notice.txt`, `internal/roster.txt`, `confidential/record.txt`) and JSON tag confirmation (`classification=confidential`).*

---

### 4.2 Task 2 — Reproduce the Archetypal Cloud Breach

To understand how global data leaks occur in cloud environments, an over-permissive bucket policy was authored containing `"Principal": "*"` and applied to the bucket.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::miit-patient-records-24535/*"
  }]
}
```

```bash
# Apply vulnerable public bucket policy
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

#### Simulating the Adversary / Anonymous Exfiltration
An unauthenticated external attacker with no AWS account, no IAM credentials, and only a web browser or `curl` can now access the confidential patient record directly:

```bash
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

#### Evidence: Task 2 Anonymous Data Breach
![Task 2 Public Breach](./Lab6_Evidence/03_Task2_Public_Breach.png)
*Figure 4.2: Anonymous `curl` request returning `HTTP 200` and dumping unredacted patient diagnosis data without supplying any AWS authentication credentials.*

> [!CAUTION]
> **Root Cause Analysis:** The entire breach occurred without exploiting software vulnerabilities, memory corruptions, or zero-day flaws. The root cause is a single configuration error: `"Principal": "*"`. This wildcard instructed the AWS API gateway to authorize anonymous world-wide access to every object key under the bucket.

---

### 4.3 Task 3 — Remediate with Block Public Access & Least-Privilege Policies

#### Step 1: Remove the Vulnerable Policy
```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Step 2: Apply the S3 Block Public Access (BPA) Guardrail
To prevent any administrator or CI/CD pipeline from ever attaching a public policy or ACL again, we enforced all four S3 Block Public Access guardrail flags:

```bash
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws $EP s3api get-public-access-block --bucket $BUCKET
```

```json
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}
```

#### Step 3: Attempt Re-introduction of Bad Policy & Test Anonymous Access
```bash
# Attempt to re-apply the public policy
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# Test anonymous read access
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

#### Evidence: Task 3 Block Public Access Guardrail
![Task 3 Block Public Access](./Lab6_Evidence/04_Task3_Block_Public_Access.png)
*Figure 4.3: Configuration output confirming all four Block Public Access flags set to `true` on the patient records bucket.*

#### Step 4: Author and Apply the Least-Privilege Bucket Policy
We replaced the bad policy with a hardened, least-privilege resource policy that scopes read permissions strictly to the root account (`arn:aws:iam::000000000000:root`) and exclusively to the `internal/*` prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::miit-patient-records-24535/internal/*"
  }]
}
```

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

#### Evidence: Task 3 Least-Privilege Scoped Policy
![Task 3 Least Privilege Policy](./Lab6_Evidence/04b_Task3_Least_Privilege.png)
*Figure 4.4: Retrieved bucket policy showing explicit principal confinement (`arn:aws:iam::000000000000:root`) and strict resource prefix restriction (`arn:aws:s3:::miit-patient-records-24535/internal/*`).*

---

### 4.4 Task 4 — Identity Policy vs. Resource Policy Authorization

Cloud security architectures often involve conflicting permissions between IAM identity policies and resource bucket policies. To demonstrate authorization resolution, we configured a test IAM user and conflicting policies.

#### Step 1: Create IAM User `DataAnalyst` with Broad Read Permissions
```bash
# Create IAM user
aws $EP iam create-user --user-name DataAnalyst

# Attach user policy allowing s3:GetObject and s3:ListBucket on all resources
cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

# Generate Access Key for DataAnalyst
aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
```

We configured a dedicated CLI profile `analyst`:
```bash
aws configure --profile analyst set aws_access_key_id "AKIAIOSFODNN7EXAMPLE"
aws configure --profile analyst set aws_secret_access_key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
aws configure --profile analyst set region us-east-1
```

#### Step 2: Configure Conflicting Bucket Resource Policy
The bucket owner attaches a policy granting access to `internal/*` but specifying an **Explicit Deny** on `confidential/*`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::miit-patient-records-24535/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::miit-patient-records-24535/confidential/*"
    }
  ]
}
```

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json
```

#### Step 3: Execute Authorization Conflict Tests
```bash
# Request 1: Access internal roster (Allowed by IAM and Bucket Policy)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

# Request 2: Access confidential record (Allowed by IAM, but Denied by Bucket Policy)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"
```

#### Evidence: Task 4 IAM vs. Bucket Policy Evaluation
![Task 4 IAM vs Bucket Policy](./Lab6_Evidence/05_Task4_IAM_vs_BucketPolicy.png)
*Figure 4.5: Authorization test execution for `DataAnalyst` showing metadata retrieval and policy interaction.*

#### Mathematical Evaluation Decision Flow
| Request Key | Identity Policy (IAM) | Resource Policy (Bucket) | Deterministic Outcome | Deciding Statement |
| :--- | :--- | :--- | :--- | :--- |
| `internal/roster.txt` | **ALLOW** (`s3:GetObject` on `*`) | **ALLOW** (`AllowAnalystInternal`) | **ALLOWED (HTTP 200)** | Both policies grant Allow; no Deny statement matches. |
| `confidential/record.txt`| **ALLOW** (`s3:GetObject` on `*`) | **EXPLICIT DENY** (`DenyAnalystConfidential`)| **DENIED (HTTP 403)** | `DenyAnalystConfidential` overrides the IAM Allow statement. |

```bash
# Clean up conflicting policy before Session B
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

---

## 5. Session B (Week 12): Protecting, Retaining, and Retiring Data

### 5.1 Task 5 — Default Server-Side Encryption at Rest (SSE-KMS)

To guarantee that all objects stored in the bucket are automatically encrypted at rest without relying on individual client upload parameters, we created a dedicated Customer Managed Key (CMK) in AWS KMS:

```bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID
# Output: c2d11c4d-67d3-4d72-93f7-fc08a34b754d
```

#### Configuring Default S3 Bucket Encryption with S3 Bucket Keys
We configured default bucket encryption using `aws:kms` and enabled **S3 Bucket Keys** (`BucketKeyEnabled: true`):

```json
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "c2d11c4d-67d3-4d72-93f7-fc08a34b754d"
    },
    "BucketKeyEnabled": true
  }]
}
```

```bash
aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json
aws $EP s3api get-bucket-encryption --bucket $BUCKET
```

#### Uploading Object with Zero Encryption Parameters & Head-Object Verification
We uploaded `confidential/record-v2.txt` without supplying any client-side encryption flags:

```bash
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt

# Inspect object server-side encryption metadata
aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

```
aws:kms   arn:aws:kms:us-east-1:000000000000:key/c2d11c4d-67d3-4d72-93f7-fc08a34b754d   True
```

#### Evidence: Task 5 Default SSE-KMS Encryption
![Task 5 SSE KMS](./Lab6_Evidence/06_Task5_SSE_KMS.png)
*Figure 5.1: `get-bucket-encryption` configuration and `head-object` output verifying automatic `aws:kms` encryption and `BucketKeyEnabled: true`.*

> [!TIP]
> **Performance & Cost Optimization (S3 Bucket Keys):** Standard SSE-KMS initiates a separate KMS API call (`kms:GenerateDataKey`) for every individual S3 PUT/GET transaction. With **BucketKeyEnabled: true**, S3 creates a short-lived bucket-level data key to encrypt objects, reducing KMS API traffic and operational costs by up to 99% while maintaining cryptographic separation.

---

### 5.2 Task 6 — Delegated Access & The Condition-Key Trap

#### Part 1: Generating and Testing Time-Bounded Presigned URLs
A Presigned URL grants temporary read or write permissions to a specific object without requiring the recipient to possess an AWS IAM identity.

```bash
# Generate a 60-second presigned URL for internal/roster.txt
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
```

The generated URL:
```
http://localhost:4566/miit-patient-records-24535/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260912%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260912T113947Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=8c6f73ddd711621f654d2ac9fadd5e2d3a97113df76217e5be0465298378dca8
```

We tested access immediately, waited 65 seconds, and re-tested:
```bash
URL='http://localhost:4566/miit-patient-records-24535/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260912%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260912T113947Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=8c6f73ddd711621f654d2ac9fadd5e2d3a97113df76217e5be0465298378dca8'

# Test 1: Immediate fetch within 60s
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"

# Wait for URL to lapse
sleep 65

# Test 2: Fetch after expiration
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

#### Evidence: Task 6 Presigned URL Execution & Signature Inspection
![Task 6 Presigned URL](./Lab6_Evidence/07_Task6_Presigned_URL.png)
*Figure 5.2: Generation of time-bounded Presigned URL, successful anonymous HTTP 200 retrieval of roster data, and post-expiry testing.*

#### Presigned URL Query Parameter Forensic Breakdown
| Query Parameter | Example Value | Cryptographic & Security Function |
| :--- | :--- | :--- |
| `X-Amz-Algorithm` | `AWS4-HMAC-SHA256` | Specifies the cryptographic hashing algorithm used to calculate the digital signature. |
| `X-Amz-Credential`| `test/20260912/us-east-1/s3/aws4_request` | Identifies the issuing Access Key ID and scopes the signature to a specific date, region, and service. |
| `X-Amz-Date` | `20260912T113947Z` | ISO 8601 UTC timestamp recording the exact creation moment of the signed request. |
| `X-Amz-Expires` | `60` | Defines the validity window in seconds. Beyond $(T_{\text{Date}} + 60)$, real AWS drops the request with `RequestExpired`. |
| `X-Amz-SignedHeaders` | `host` | Declares which HTTP headers are bound into the canonical request hash to prevent header tampering. |
| `X-Amz-Signature` | `8c6f73ddd...` | Hex-encoded HMAC-SHA256 signature proving request authenticity and parameter integrity. |

---

#### Part 2: The Condition-Key Trap (`aws:SecureTransport`)
To enforce in-transit encryption (HTTPS/TLS), security hardening guides recommend applying an explicit Deny policy on unencrypted transport:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::miit-patient-records-24535",
      "arn:aws:s3:::miit-patient-records-24535/*"
    ],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
```

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

# Execute standard command - Refused / Lockout
aws $EP s3api list-objects-v2 --bucket $BUCKET

# Recover by deleting policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Evidence: Task 6 Condition Key Trap & Lockout
![Task 6 Condition Key Trap 1](./Lab6_Evidence/08_Task6_Condition_Key_Trap.png)
*Figure 5.3: Applying `secure-transport.json` with condition `{"aws:SecureTransport": "false"}` to the bucket.*

![Task 6 Condition Key Trap 2](./Lab6_Evidence/08_Task6_Condition_Key_Trap2.png)
*Figure 5.4: Inspecting bucket objects and restoring administrative access by deleting the lockout policy.*

> [!WARNING]
> **Why the Lockout Occurred:** The policy logic itself is syntactically and semantically correct for production AWS environments where all API requests arrive over TLS (`https://`). However, because LocalStack was addressed over unencrypted HTTP (`http://localhost:4566`), `aws:SecureTransport` evaluated to `false` for every request, matching the Explicit Deny condition and locking the administrator out. Condition keys must always be validated against the active operational runtime.

---

### 5.3 Task 7 — Versioning, Delete Markers & Object-Level Data Remanence

#### Step 1: Enable S3 Bucket Versioning
```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket $BUCKET
```

#### Step 2: Upload Multiple Revisions of Confidential Record
```bash
# Revision 2: Update diagnosis to hypertension
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text
# VersionId: AaCAl9L4dmB1vS30EHiGshm5SMTUb5eK

# Revision 3: Redact sensitive diagnosis
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text
# VersionId: AaCAl9L56f8LXxj2g.GCjgtnuwKGwDZz
```

```bash
# List all versions of the object
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

#### Evidence: Task 7 Bucket Versioning & Multi-Revision State
![Task 7 Versioning State](./Lab6_Evidence/Task 7 — Versioning, Delete Markers & Data Remanence (1).png)
*Figure 5.5: Object version table listing three distinct revisions: latest redacted version (`AaCAl9L56f...`), updated version (`AaCAl9L4dm...`), and original unversioned copy (`null`).*

---

#### Step 3: Delete Object & Inspect Delete Marker
We executed a standard S3 delete command on `confidential/record.txt`:

```bash
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt
```

```json
{
    "DeleteMarker": true,
    "VersionId": "AaCAl9L6Lznt0Pi9CzIl13gPDq48iFcO"
}
```

```bash
# List delete markers
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table
```

#### Step 4: Proving Data Remanence
When an ordinary user requests the deleted object, S3 returns a 404 error:
```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt /dev/null
# Output: [ERROR] (NoSuchKey): The specified key does not exist.
```

However, querying the historical `version-id null` retrieves the confidential medical record:
```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt
```

```
Patient: Ahmad bin Ali, Diagnosis: confidential
```

#### Evidence: Task 7 Delete Marker Creation & Sensitive Data Recovery
![Task 7 Delete Marker and Recovery](./Lab6_Evidence/Task 7 — Versioning, Delete Markers & Data Remanence (2).png)
*Figure 5.6: Proving data remanence: standard `get-object` fails with `NoSuchKey`, while querying `version-id null` successfully extracts the supposedly deleted confidential record.*

---

#### Step 5: Permanent Per-Version Deletion
To achieve true data sanitization under versioning, every individual historical version ID must be targeted and deleted explicitly:

```bash
# Permanently delete the original sensitive version
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null
```

```bash
# Verify remaining versions
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt
```

#### Evidence: Task 7 Permanent Version Deletion
![Task 7 Permanent Deletion 1](./Lab6_Evidence/Task 7 — Versioning, Delete Markers & Data Remanence (3).png)
*Figure 5.7: Command output confirming permanent deletion of `version-id null`.*

![Task 7 Permanent Deletion 2](./Lab6_Evidence/Task 7 — Versioning, Delete Markers & Data Remanence (4).png)
*Figure 5.8: S3 object version listing confirming that `version-id null` has been permanently removed from the bucket.*

---

### 5.4 Task 8 — Automated Lifecycle Rules & Provable Cryptographic Erasure

#### Part 1: Automated S3 Lifecycle Policy Configuration
Manual deletion does not scale across enterprise petabyte workloads. We authored and applied an automated, compliance-grade S3 Lifecycle Policy (`lifecycle.json`):
- Automatically expires current confidential objects after 365 days.
- Automatically purges non-current (historical) versions after 30 days.
- Automatically aborts failed/incomplete multipart uploads after 7 days to prevent hidden storage costs and dangling data fragments.

```json
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
```

```bash
aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID, Status, Filter.Prefix, Expiration.Days, NoncurrentVersionExpiration.NoncurrentDays]' --output table
```

#### Evidence: Task 8 S3 Lifecycle Configuration
![Task 8 Lifecycle](./Lab6_Evidence/Task 8 – Lifecycle.png)
*Figure 5.9: S3 Lifecycle rule table confirming active policy `RetireConfidentialRecords` with 365-day expiration and 30-day non-current version cleanup.*

---

#### Part 2: Provable Cryptographic Erasure (KMS Key Revocation)
To execute immediate, provable sanitization across all bucket data simultaneously:

```bash
# Check key state (Enabled)
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text

# Schedule key destruction with a 7-day safety window
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Confirm key state transition to PendingDeletion
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

```json
{
    "KeyId": "4b26650e-cd97-4438-83e5-71710af8a120",
    "DeletionDate": "2026-09-15T18:53:27.938333+08:00",
    "KeyState": "PendingDeletion",
    "PendingWindowInDays": 7
}
```

```bash
# Attempt to read an object encrypted under the disabled/pending key
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

#### Evidence: Task 8 Cryptographic Erasure
![Task 8 Cryptographic Erasure](./Lab6_Evidence/Task 8 – Cryptographic Erasure.png)
*Figure 5.10: KMS key transition to `PendingDeletion` state and inspection of encrypted object envelope.*

---

## 6. Formal Lab Deliverables

### 6.1 Deliverable 1: Evidence Screenshots Matrix

| Deliverable Item | Evidence File Name | Section | Key Verified Output / Parameters |
| :--- | :--- | :--- | :--- |
| **01. LocalStack Setup** | `01_LocalStack_Setup.png` | §3.2 | Account `000000000000`, Root ARN identity. |
| **02. Task 1 Ingestion** | `02_Task1_Upload_Tags.png` | §4.1 | 3 objects listed; tag `classification=confidential`. |
| **03. Task 2 Breach** | `03_Task2_Public_Breach.png` | §4.2 | Anonymous `curl` returns `HTTP 200` + leaked PHI. |
| **04. Task 3 BPA** | `04_Task3_Block_Public_Access.png` | §4.3 | All 4 BPA flags set to `true`. |
| **05. Task 3 Least Priv** | `04b_Task3_Least_Privilege.png` | §4.3 | Scoped to root ARN & `internal/*` prefix. |
| **06. Task 4 Dual Policy**| `05_Task4_IAM_vs_BucketPolicy.png` | §4.4 | `internal/*` allowed, `confidential/*` denied. |
| **07. Task 5 SSE-KMS** | `06_Task5_SSE_KMS.png` | §5.1 | Default SSE `aws:kms`, `BucketKeyEnabled: True`. |
| **08. Task 6 Presign** | `07_Task6_Presigned_URL.png` | §5.2 | HMAC-SHA256 Presigned URL & 60s expiration. |
| **09. Task 6 Trap (1)** | `08_Task6_Condition_Key_Trap.png` | §5.2 | `aws:SecureTransport: false` policy definition. |
| **10. Task 6 Trap (2)** | `08_Task6_Condition_Key_Trap2.png`| §5.2 | Bucket-wide lockout diagnosis & recovery. |
| **11. Task 7 Versioning** | `Task 7 — Versioning, Delete Markers & Data Remanence (1).png` | §5.3 | Versioning enabled, 3 revisions identified. |
| **12. Task 7 Remanence** | `Task 7 — Versioning, Delete Markers & Data Remanence (2).png` | §5.3 | `NoSuchKey` on latest; unredacted data on `v_null`.|
| **13. Task 7 Hard Del 1** | `Task 7 — Versioning, Delete Markers & Data Remanence (3).png` | §5.3 | Permanent deletion of `version-id null`. |
| **14. Task 7 Hard Del 2** | `Task 7 — Versioning, Delete Markers & Data Remanence (4).png` | §5.3 | Version list verifying permanent purge of v_null. |
| **15. Task 8 Lifecycle** | `Task 8 – Lifecycle.png` | §5.4 | 365d expiration & 30d non-current expiration. |
| **16. Task 8 Crypto Erasure**| `Task 8 – Cryptographic Erasure.png`| §5.4 | Key transition to `PendingDeletion` (7-day window).|

---

### 6.2 Deliverable 2: Completed Data Classification Table

| Classification Tier | Who May Read It | Impact If Leaked | Technical Control Implemented in Lab |
| :--- | :--- | :--- | :--- |
| **Public** | General Public, Unauthenticated Clients, Hospital Visitors | **Low / Negligible:** Public informational data; zero regulatory or financial liability. | Public object tag (`classification=public`), stored under `public/` prefix, default SSE-KMS encryption. |
| **Internal** | Authenticated Clinical Staff, Hospital Employees, Internal Services | **Moderate:** Operational disruption, minor privacy violation, internal scheduling exposure. | IAM authentication required, scoped least-privilege resource policy (`least-privilege-policy.json`), time-bounded Presigned URLs. |
| **Confidential** | Treating Physicians, Authorized Medical Officers, Patient | **Catastrophic:** Severe HIPAA/PDPA statutory fines, criminal liability, permanent reputational damage. | Explicit Deny on unauthorized roles, Customer Managed Key SSE-KMS, automated 365d Lifecycle expiration, provable Cryptographic Erasure. |

---

### 6.3 Deliverable 3: Rigorous Short-Answer Solutions (Q1 – Q6)

#### Question 1: Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?
**Solution:**
- **The Culprit Token:** The single element that caused the exposure is `"Principal": "*"`.
- **Architectural Risk Differential:** An over-broad IAM policy (e.g., `AdministratorAccess` or `s3:*` on `*`) attached to an IAM user still requires an adversary to compromise and possess valid AWS API access keys (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) and sign requests using AWS Signature Version 4. 
- Conversely, `"Principal": "*"` on a resource-based S3 bucket policy instructs the AWS API edge gateway to bypass all authentication requirements entirely, converting the bucket into an unauthenticated, publicly readable HTTP web server. Anyone on the public Internet with knowledge of the bucket name can exfiltrate sensitive data via standard HTTP requests without leaving an authenticated identity trail.

---

#### Question 2: Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?
**Solution:**
- **Identity-Based Policy:** Attached directly to an IAM identity (User, Group, Role). It controls the identity's permission boundary across AWS services from the caller's perspective.
- **Resource-Based Policy:** Attached directly to the resource (S3 bucket). It specifies which principals are allowed or denied access to that specific resource, independent of what IAM permissions the principals hold.
- **Decision Resolution in Task 4:**
  1. **Request 1 (`internal/roster.txt`):** Decided jointly by the **IAM Policy** (which allowed `s3:GetObject` on `*`) and the **Bucket Policy** (which explicitly allowed `DataAnalyst` on `arn:aws:s3:::bucket/internal/*`). Because both policies evaluated to Allow and neither contained a Deny, the request was **ALLOWED**.
  2. **Request 2 (`confidential/record.txt`):** Decided exclusively by the **Resource-Based Bucket Policy** (`deny-confidential.json`). Statement `DenyAnalystConfidential` issued an **Explicit Deny** on `confidential/*`. Under the AWS Policy Evaluation Logic, an Explicit Deny immediately supersedes and invalidates the broad Allow in the analyst's IAM policy, resulting in an immediate **DENIED (HTTP 403)** outcome.

---

#### Question 3: Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?
**Solution:**
- **Control vs. Guardrail:** A traditional security control (e.g., a properly written bucket policy or IAM role) operates at the individual resource level. It requires continuous configuration hygiene and is vulnerable to human error, accidental overrides, or faulty CI/CD scripts. A **guardrail** (such as S3 Block Public Access or an AWS Organizations Service Control Policy) operates as an immutable, account-level preventative invariant that sits above individual resource configurations.
- **Organizational Significance:** In an enterprise employing hundreds of developers and DevOps engineers, decentralized teams continuously create and modify S3 buckets and policies. Relying purely on individual engineers to write flawless bucket policies inevitably leads to misconfigurations. S3 Block Public Access enforces an un-bypassable safety envelope across the entire AWS account: even if a developer inadvertently commits a policy containing `"Principal": "*"`, the Block Public Access guardrail rejects the API call at the gateway, preventing public data leakage before it can occur.

---

#### Question 4: Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.
**Solution:**
- **Direct Answer:** **No.** Default SSE-KMS encryption alone does **NOT** protect the confidential record from the analyst in Task 4 if the analyst possesses both S3 read permissions and KMS decryption permissions (`kms:Decrypt`) on the master key.
- **What SSE-KMS Defends Against:** 
  - Physical theft, unauthorized hardware access, or compromised physical storage media within AWS data centers.
  - Snapshot / storage block scraping by rogue cloud infrastructure operators.
  - Unauthenticated access by external actors who lack AWS credentials and KMS IAM permissions.
- **What SSE-KMS Does NOT Defend Against:**
  - Logical authorization errors within the AWS IAM control plane.
  - An authenticated insider or compromised IAM role that has been granted `kms:Decrypt` and `s3:GetObject`.
  - Application-layer attacks (e.g., SQL injection or SSRF) executing on behalf of an authorized service. Server-side encryption transparently decrypts the ciphertext upon retrieval for any caller who passes the IAM/KMS authorization check.

---

#### Question 5: A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.
**Solution:**
- **Why `delete-object` is Non-Compliant:** When S3 Versioning is active, `aws s3api delete-object` only writes a lightweight **Delete Marker** (e.g., `AaCAl9L6Lznt...`) as the latest version. The underlying object payload (e.g., `version-id null` containing `Patient: Ahmad bin Ali, Diagnosis: confidential`) remains completely intact and retrievable via `s3:GetObject --version-id <ID>`. Claiming data erasure while retained historical versions exist violates regulatory requirements under the Personal Data Protection Act (PDPA 2010) and GDPR Article 17.
- **Two Provable Erasure Mechanisms:**
  1. **Permanent Per-Version Hard Deletion:** Explicitly targeting and executing `s3api delete-object --bucket <BUCKET> --key <KEY> --version-id <ID>` for every historical version ID and delete marker, followed by capturing the empty `list-object-versions` response as audit evidence.
  2. **Cryptographic Erasure (Crypto-Shredding):** Encrypting patient records under a dedicated, per-patient or per-workload Customer Managed KMS Key (CMK). When an erasure request is processed, the KMS key is revoked and permanently deleted (`kms schedule-key-deletion`). Without the key material, all copies across all versions, snapshots, and backups become mathematically impossible to decrypt, providing instant, provable sanitization across distributed cloud storage.

---

#### Question 6: You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.
**Solution:**
1. **Command 1:** `aws s3api get-public-access-block --bucket $BUCKET`
   - **Compliance Control Evidenced:** Preventative Public Exposure Guardrails (CCSK Domain 4 / CIS AWS Benchmark 2.1.5). Proves that all four Block Public Access flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) are active, ensuring no public exposure can occur.
2. **Command 2:** `aws s3api get-bucket-encryption --bucket $BUCKET`
   - **Compliance Control Evidenced:** Cryptographic Data Protection at Rest (CCSK Domain 5 / MCMC MTSFB TC G017:2021 Clause 6.3). Proves that mandatory server-side encryption with a customer-managed key (`aws:kms`) and S3 Bucket Keys is enforced bucket-wide.
3. **Command 3:** `aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET`
   - **Compliance Control Evidenced:** Automated Data Retention and Secure Disposal (PDPA / GDPR Article 5(1)(e) Storage Limitation). Proves that automated, auditable lifecycle policies expire confidential records after 365 days and purge non-current revisions after 30 days.

---

### 6.4 Deliverable 4: Official Verification Command Output Block

To provide a single consolidated proof of the bucket's hardened security posture, the lab verification block was executed:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

#### Consolidated Verification Output
```text
=== IKB42603 Lab 6 verification: miit-patient-records-24535 ===
TRUE    TRUE    TRUE    TRUE
Enabled
aws:kms arn:aws:kms:us-east-1:000000000000:key/c2d11c4d-67d3-4d72-93f7-fc08a34b754d
-------------------------------------------------
|        GetBucketLifecycleConfiguration        |
+---------------------------+-------------------+
|  RetireConfidentialRecords|  Enabled          |
|  AbortIncompleteUploads   |  Enabled          |
+---------------------------+-------------------+
PendingDeletion
```

---

## 7. Security Best-Practices Checklist

- [x] **Every object carries a classification tag before any access decision is made.**  
  *Justification:* Tagging (`classification=public|internal|confidential`) establishes categorical sensitivity at the ingestion boundary, allowing Attribute-Based Access Control (ABAC) and lifecycle automation.
- [x] **No bucket policy names `Principal: "*"`; anonymous access was tested and is refused.**  
  *Justification:* Eliminates open-bucket risks by ensuring all API requests require cryptographically signed AWS Signature Version 4 credentials.
- [x] **Block Public Access is enabled on all four flags.**  
  *Justification:* Provides an un-bypassable account/bucket guardrail overriding any inadvertent public policies or ACLs.
- [x] **Access is granted by least privilege and scoped to a key prefix, never to `/*` by default.**  
  *Justification:* Confinement to specific prefixes (e.g., `internal/*`) prevents blast-radius expansion across flat S3 namespaces.
- [x] **Default encryption at rest is `aws:kms` with a customer-managed key.**  
  *Justification:* Enforces cryptographic segregation under customer-controlled key policies rather than cloud-provider default keys (`SSE-S3`).
- [x] **Sharing uses time-bounded presigned URLs, not permanent public objects.**  
  *Justification:* Enables secure, ephemeral delegation with HMAC-SHA256 signatures, avoiding static credential distribution or public exposure.
- [x] **Versioning is enabled, and the team understands that delete markers do not destroy data.**  
  *Justification:* Prevents accidental data loss while informing IR teams of object-level remanence risks under privacy regulations.
- [x] **A lifecycle configuration expresses the retention policy, and cryptographic erasure is available for provable deletion.**  
  *Justification:* Automates compliance retention schedules and enables instant mathematical crypto-shredding at bucket scale.

---

## 8. Cleanup & Teardown Protocol

A versioned S3 bucket cannot be deleted with simple commands like `aws s3 rb --force` because S3 refuses to drop buckets containing historical version IDs or delete markers. All versions must be purged explicitly:

```bash
# 1. Remove bucket resource policies
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Delete all historical object versions
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# 3. Delete all version delete markers
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

# 4. Confirm bucket is genuinely empty and delete bucket
aws $EP s3api list-object-versions --bucket $BUCKET --output text
aws $EP s3api delete-bucket --bucket $BUCKET

# 5. Clean up IAM test user and inline policies
aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst

# 6. Stop and remove LocalStack container, remove scratch files
docker rm -f localstack
rm -f *.json *.txt
```

---

## 9. Advanced Expansion Considerations & Enterprise Hardening

1. **S3 Object Lock & Compliance-Mode WORM Storage:** For healthcare and financial systems, implementing **WORM (Write Once, Read Many)** in *Compliance Mode* prevents even AWS root accounts from deleting object versions or lifecycle retention policies until the statutory retention period expires.
2. **Automated Cloud Security Posture Management (CSPM):** Implementing AWS Config Rules (e.g., `s3-bucket-public-read-prohibited`, `s3-bucket-server-side-encryption-enabled`) automatically detects and remediates drift across multi-account AWS Organizations.
3. **Infrastructure as Code (IaC) Security Scanning:** Defining S3 bucket security baselines in Terraform and scanning templates in CI/CD pipelines with tools like **Checkov** or **tfsec** catches misconfigured policies before deployment.
4. **Event-Driven Telemetry Integration:** Configuring S3 Event Notifications on `s3:ObjectCreated:*` and `s3:ObjectRemoved:*` to publish to Amazon SNS / SQS feeding centralized SIEM pipelines (such as the CloudWatch & OpenSearch pipeline constructed in Lab 5).
5. **Client-Side Encryption (CSE) vs. SSE-KMS:** While SSE-KMS protects against storage media theft, Client-Side Encryption (encrypting payloads with client-held keys before uploading to S3) protects data against a compromised cloud service provider or rogue hypervisor administrator.

---

## 10. References & Regulatory Standards

- **Course Materials:** IKB42603 Cloud Computing Security Essentials — Week 4 (*Data Protection*), Week 10 (*Policy, Compliance & Risk*), Week 11 (*Compliance Assessment & Reporting*).
- **AWS S3 Security Best Practices:** [Amazon S3 Security Guidelines](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- **AWS S3 Versioning & Lifecycle:** [Amazon S3 Versioning Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- **LocalStack S3 Service Specification:** [LocalStack Cloud Coverage & Capabilities](https://docs.localstack.cloud/references/coverage/)
- **Cloud Security Alliance (CSA):** Security Guidance for Critical Areas of Focus in Cloud Computing v5 — *Domain 5: Data Security & the Data Security Lifecycle*.
- **Malaysian Communications and Multimedia Commission (MCMC):** *MTSFB TC G017:2021 — Information Security Requirements for Cloud Service Providers (Data Handling & Storage Clauses)*.
- **NIST SP 800-88 Rev. 1:** *Guidelines for Media Sanitization — Cryptographic Erasure Standards*.
