# LAB 1: Cloud Account Security, Identity & Access Management (IAM)
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Student Name:** Muhammad Haqiem Fauzi  
**Topic:** Identity Governance and Least Privilege — LocalStack IAM & Kubernetes RBAC  

---

## Table of Contents
1. [Executive Summary & Lab Objectives](#1-executive-summary--lab-objectives)
2. [Task 1: Map the Cloud Identity Landscape](#2-task-1-map-the-cloud-identity-landscape)
3. [Session A: Cloud Identity with LocalStack (Tasks 2 – 4)](#3-session-a-cloud-identity-with-localstack)
   - [One-Time Environment Setup & Baseline Identity](#31-one-time-environment-setup--baseline-identity)
   - [Task 2: Create a Least-Privilege Admin (Stop Using Root)](#32-task-2-create-a-least-privilege-admin-stop-using-root)
   - [Task 3: Enforce Least Privilege with a Scoped Policy](#33-task-3-enforce-least-privilege-with-a-scoped-policy)
   - [Task 4: Credential Hygiene & Access Key Lifecycle](#34-task-4-credential-hygiene--access-key-lifecycle)
4. [Session B: Enforced Access Control with Kubernetes RBAC (Tasks 5 – 7)](#4-session-b-enforced-access-control-with-kubernetes-rbac)
   - [Setup: Local Kubernetes Cluster via KinD](#41-setup-local-kubernetes-cluster-via-kind)
   - [Task 5: Multi-Tenancy & Environment Separation with Namespaces](#42-task-5-multi-tenancy--environment-separation-with-namespaces)
   - [Task 6: Define Role & RoleBinding (Least Privilege)](#43-task-6-define-role--rolebinding-least-privilege)
   - [Task 7: Verification & Testing Access Boundaries](#44-task-7-verification--testing-access-boundaries)
5. [Authentication vs Authorization Deep Dive](#5-authentication-vs-authorization-deep-dive)
6. [Lab Deliverables & Short-Answer Questions](#6-lab-deliverables--short-answer-questions)
7. [Verification Artifacts & RBAC Manifest](#7-verification-artifacts--rbac-manifest)
8. [Security Best-Practices Checklist](#8-security-best-practices-checklist)
9. [Cleanup & Teardown](#9-cleanup--teardown)
10. [Conclusion & Advanced Security Considerations](#10-conclusion--advanced-security-considerations)

---

## 1. Executive Summary & Lab Objectives

### 1.1 Overview
This laboratory exercise implements identity governance, access boundary controls, and the principle of least privilege across two distinct cloud operational layers:
1. **Cloud Management Plane (AWS IAM simulated via LocalStack):** Defining granular identities, delegating permissions through IAM user groups, and scoping managed policies to eliminate everyday root account usage and reduce the organizational blast radius.
2. **Container Orchestration Plane (Kubernetes RBAC via KinD):** Enforcing cryptographic service account boundaries, namespace isolation (`dev` vs. `prod`), and fine-grained API authorization via Kubernetes `Roles` and `RoleBindings`.

### 1.2 Learning Outcomes (CLO2 Mapping)
- **CLO2:** Construct secure cloud operations that safeguard data integrity.
- **VBE3 (Integrity):** Maintain credential hygiene, avoid root compromise, and audit identity access tokens.
- **SC8 (Integrated Problem-Solving):** Solve multi-tenant isolation challenges using RBAC and policy-as-code principles.

---

## 2. Task 1: Map the Cloud Identity Landscape

Understanding the core building blocks of cloud identity is fundamental before constructing access architectures.

| Concept | AWS IAM Term | Purpose & Security Function |
| :--- | :--- | :--- |
| **All-powerful owner** | `Root user` | The initial account owner identity created when the cloud account is established. Has complete, unrestricted access to all account resources, billing, and configurations. It cannot be restricted by IAM policies and should **never** be used for daily operational tasks. |
| **Human / App identity** | `IAM User` | A long-term identity entity representing a specific person or service/application that requires persistent credentials (console password or access keys) to interact with AWS resources. |
| **Permission bundle** | `IAM Policy` | A JSON document that explicitly declares `Effect` (`Allow`/`Deny`), `Action` (API operations), `Resource` (ARNs), and optional `Condition` statements to grant or restrict permissions. |
| **Collection of users** | `IAM Group` | An administrative collection of IAM users used to attach policies to multiple identities simultaneously, ensuring consistent permission assignment and eliminating permission drift across team members. |
| **Temporary identity** | `IAM Role` | A dynamically assumable identity with no permanent credentials. Provides short-lived security tokens via AWS STS (Security Token Service) for federated users, AWS services (e.g., EC2, Lambda), or cross-account delegation. |

---

## 3. Session A: Cloud Identity with LocalStack

### 3.1 One-Time Environment Setup & Baseline Identity
LocalStack provides an offline, AWS-compatible cloud API simulator running inside Docker, allowing safe testing of IAM configurations without incurring real-world cloud expenses or risk.

#### Commands Executed:
```bash
# 1. Start LocalStack container
docker run -d --name localstack -p 4566:4566 localstack/localstack

# 2. Verify health endpoint
curl http://localhost:4566/_localstack/health

# 3. Configure mock AWS CLI credentials
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# 4. Verify initial caller identity (Root account baseline)
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

#### Evidence 1: Baseline Identity Verification (`sts get-caller-identity`)
![Baseline Identity Verification](<evidence/One-Time Environment Setup.jpg>)

**Observation:**  
The output confirms that the CLI initially operates under the omnipotent root identity:
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```
*Security Risk:* Operating as `arn:aws:iam::000000000000:root` introduces severe operational risks because any compromised credential or errant command has absolute authority over the entire cloud infrastructure.

---

### 3.2 Task 2: Create a Least-Privilege Admin (Stop Using Root)
To mitigate root user vulnerability, we construct a dedicated administrative group (`Admins`), attach the AWS-managed `AdministratorAccess` policy to the group, create an individualized administrator user (`CloudAdmin_Haqiem`), and add the user to the group.

#### Commands Executed:
```bash
# Set endpoint variable
EP='--endpoint-url=http://localhost:4566'

# 2.1 Create the Admins group & attach AdministratorAccess
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2.2 Create personal admin user
aws $EP iam create-user --user-name CloudAdmin_Haqiem

# 2.3 Add admin user to the Admins group
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_Haqiem

# 2.4 Verify group membership
aws $EP iam get-group --group-name Admins
```

#### Evidence 2: Admins Group Membership Verification (`get-group Admins`)
![Admins Group Membership Verification](evidence/2_get-group-Admins.jpg)

**CLI Output Captured:**
```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_Haqiem",
            "UserId": "0p168t5q1kaqi2i1xg7e",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_Haqiem",
            "CreateDate": "2026-08-10T09:28:28.687000+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "jvtyalwecxdlg7ajj1ux",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-09T15:44:24.474000+00:00"
    }
}
```

**Security Analysis:**
- **Separation of Duties & Group-Based Access Control:** Attaching policies to groups rather than direct inline user attachments ensures role consistency, simplified auditing, and zero permission drift when administrators are onboarded or offboarded.
- **Auditability:** Actions performed by `CloudAdmin_Haqiem` produce individualized log traces in CloudTrail / audit logs, establishing individual accountability.

---

### 3.3 Task 3: Enforce Least Privilege with a Scoped Policy
A standard data analyst identity requires visibility into cloud data stores (e.g., S3 storage) without the ability to modify, delete, create resources, or alter IAM security policies.

#### Commands Executed:
```bash
# 3.1 Create analyst user
aws $EP iam create-user --user-name Analyst_Fauzi

# 3.2 Attach scoped read-only policy
aws $EP iam attach-user-policy --user-name Analyst_Fauzi \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 3.3 Verify attached policies
aws $EP iam list-attached-user-policies --user-name Analyst_Fauzi
```

#### Evidence 3: Analyst Attached Policies (`list-attached-user-policies`)
![Analyst Attached Policies](evidence/3_List-attached-policies.jpg)

**CLI Output Captured:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

**Blast Radius & Least Privilege Analysis:**
- **Blast Radius Reduction:** If the credentials of `Analyst_Fauzi` are compromised by an adversary, the attacker cannot delete buckets, tamper with objects, spin up costly GPU/EC2 compute instances for cryptomining, or escalate privileges by creating admin policies.
- **Read-Only Containment:** The attacker is strictly confined to read operations on S3. Critical infrastructure and other cloud services (IAM, VPC, RDS, Lambda) remain completely inaccessible.

---

### 3.4 Task 4: Credential Hygiene & Access Key Lifecycle
Programmatic interaction relies on Access Key IDs and Secret Access Keys. Long-lived credentials represent a critical threat vector if inadvertently leaked (e.g., committed to public GitHub repositories).

#### Commands Executed:
```bash
# 4.1 Create programmatic access key
aws $EP iam create-access-key --user-name Analyst_Fauzi

# 4.2 List active access keys
aws $EP iam list-access-keys --user-name Analyst_Fauzi

# 4.3 Rotate / Deactivate compromised or old access key
aws $EP iam update-access-key --user-name Analyst_Fauzi \
    --access-key-id <ACCESS_KEY_ID> --status Inactive
```

**Credential Hygiene Best Practices:**
1. **Rotate Keys Regularly:** Deactivate old keys before permanent deletion to verify that running applications are not broken.
2. **Never Hardcode Secrets:** Utilize environment variables, secrets managers (e.g., AWS Secrets Manager, HashiCorp Vault), or instance profiles / IAM roles.
3. **Prefer Short-Lived IAM Roles:** Avoid static long-term credentials entirely by using STS temporary tokens (OpenID Connect / IAM Roles for Service Accounts).

---

## 4. Session B: Enforced Access Control with Kubernetes RBAC

LocalStack simulates AWS IAM mechanics, but Kubernetes RBAC enforces access control in real time by actively intercepting and rejecting unauthorized API requests.

### 4.1 Setup: Local Kubernetes Cluster via KinD
```bash
# Provision Kubernetes cluster inside Docker
kind create cluster --name ccse-lab1

# Verify cluster nodes and context
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

---

### 4.2 Task 5: Multi-Tenancy & Environment Separation with Namespaces
Namespaces partition a single physical cluster into isolated virtual environments, preventing resource name collisions and establishing clear access boundaries.

#### Commands Executed:
```bash
# Create isolated environments
kubectl create namespace dev
kubectl create namespace prod

# List active namespaces
kubectl get namespaces
```

---

### 4.3 Task 6: Define Role & RoleBinding (Least Privilege)
We create a developer service account (`dev-user`) in namespace `dev`, define a scoped `Role` (`pod-reader`) restricted to read-only pod operations, and bind the role to the service account using a `RoleBinding`.

#### Commands Executed:
```bash
# 6.1 Create ServiceAccount in dev namespace
kubectl create serviceaccount dev-user -n dev

# 6.2 Create Role granting read-only pod access
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods

# 6.3 Bind the Role to the dev-user ServiceAccount
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

---

### 4.4 Task 7: Verification & Testing Access Boundaries
To validate RBAC enforcement, we query the Kubernetes API server using `kubectl auth can-i` impersonating the `dev-user` service account (`system:serviceaccount:dev:dev-user`).

#### Verification Commands:
```bash
SA=system:serviceaccount:dev:dev-user

# Test 1: List pods in dev (Permitted)
kubectl auth can-i list pods -n dev --as=$SA

# Test 2: List pods in prod (Cross-namespace access - Forbidden)
kubectl auth can-i list pods -n prod --as=$SA

# Test 3: Create / Delete pods in dev (Write operation - Forbidden)
kubectl auth can-i create pods -n dev --as=$SA
kubectl auth can-i delete pods -n dev --as=$SA
```

#### Evidence 4: Kubernetes RBAC Policy Enforcement (`kubectl auth can-i`)
![Kubernetes RBAC Authorization Test](evidence/4_kubectl-auth-can-i.jpg)

**CLI Output Captured:**
```text
┌──(kali㉿kali)-[~]
└─$ kubectl auth can-i list pods --as=system:serviceaccount:dev:dev-user -n dev
yes

┌──(kali㉿kali)-[~]
└─$ kubectl auth can-i list pods --as=system:serviceaccount:dev:dev-user -n prod
no

┌──(kali㉿kali)-[~]
└─$ kubectl auth can-i create pods --as=system:serviceaccount:dev:dev-user -n dev
no
```

---

## 5. Authentication vs Authorization Deep Dive

The testing in Task 7 clearly illustrates the boundary between **Authentication (AuthN)** and **Authorization (AuthZ)** within cloud architectures:

```
+-------------------------------------------------------------------------------+
|                             Incoming API Request                              |
+-------------------------------------------------------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |   Step 1: Authentication (AuthN)  |
                     |      "Who is making the request?" |
                     +-----------------------------------+
                                       |
                   [Pass: Identity verified as `dev-user`]
                                       |
                                       v
                     +-----------------------------------+
                     |   Step 2: Authorization (AuthZ)   |
                     |       "Is this action allowed?"   |
                     +-----------------------------------+
                                       |
       +-------------------------------+-------------------------------+
       |                               |                               |
[list pods in dev]            [list pods in prod]             [create/delete in dev]
       |                               |                               |
       v                               v                               v
 +-----------+                   +-----------+                   +-----------+
 |  ALLOWED  |                   |  DENIED   |                   |  DENIED   |
 |   (yes)   |                   |   (no)    |                   |   (no)    |
 +-----------+                   +-----------+                   +-----------+
```

### Analysis of the Three Test Cases:
1. **Test 1 (`list pods -n dev` -> `yes`):**  
   - *AuthN:* Passes. The API server authenticates the client as `system:serviceaccount:dev:dev-user`.  
   - *AuthZ:* Evaluates `RoleBinding` `dev-user-binding` -> points to `Role` `pod-reader` in namespace `dev` -> rule permits verbs `[get, list, watch]` on resource `pods`. Decision: **ALLOW**.
2. **Test 2 (`list pods -n prod` -> `no`):**  
   - *AuthN:* Passes. Identity is still authenticated as `dev-user`.  
   - *AuthZ:* Evaluates policies in namespace `prod`. No `RoleBinding` or `ClusterRoleBinding` grants `dev-user` permissions in the `prod` namespace. Decision: **DENY (Implicit Deny)**.
3. **Test 3 (`create / delete pods -n dev` -> `no`):**  
   - *AuthN:* Passes.  
   - *AuthZ:* Evaluates `pod-reader` in namespace `dev`. Permitted verbs are strictly `[get, list, watch]`. The verbs `create` and `delete` are absent. Decision: **DENY (Least Privilege Enforced)**.

---

## 6. Lab Deliverables & Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?
**Answer:**  
Attaching policies directly to individual users leads to **permission drift**, where users accumulate excessive, unmonitored privileges over time. Managing permissions via groups provides:
1. **Centralized Administration:** Permissions are updated in a single location (`IAM Group`), automatically propagating to all members.
2. **Role-Based Consistency:** Ensures all employees fulfilling the same job function (e.g., Developers, Auditors, SysAdmins) have identical, auditable baselines.
3. **Seamless Lifecycle Management:** Onboarding a new hire simply requires adding them to the group; offboarding or role transition requires removing them from the group, instantly revoking all associated permissions without orphan policy risks.

---

### Q2. What is the difference between an IAM User and an IAM Role?
**Answer:**  
- **IAM User:** Represents a permanent, long-term identity (typically a specific human or legacy service) with static long-lived credentials (console password or secret access keys).
- **IAM Role:** A dynamic identity that is assumed by trusted entities (IAM users, EC2 instances, Lambda functions, or external federated identities) on demand. It possesses **no long-term credentials**; instead, AWS STS generates temporary, short-lived security credentials (valid from minutes to hours), drastically reducing credential leakage vulnerabilities.

---

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
**Answer:**  
The **Principle of Least Privilege (PoLP)** dictates that an identity must only be granted the minimum permissions necessary to complete its assigned job duties.  
- In this lab, `Analyst_Fauzi` was exclusively granted `AmazonS3ReadOnlyAccess`.
- **Blast Radius Reduction:** If an attacker compromises the Analyst’s credentials via phishing or key theft, the damage is strictly constrained to reading S3 data. The attacker **cannot**:
  - Delete or overwrite S3 objects (protecting data integrity).
  - Provision compute resources (preventing financial denial-of-service/cryptojacking).
  - Alter IAM policies or create backdoor accounts (preventing privilege escalation).  
This isolates the breach and prevents lateral movement across the cloud infrastructure.

---

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?
**Answer:**  
- **Role:** An RBAC resource that defines **what** operations can be performed. It contains a collection of permission rules specifying API groups, resources (e.g., `pods`, `services`), and verbs (e.g., `get`, `list`, `create`, `delete`) scoped within a specific namespace.
- **RoleBinding:** The bridge that defines **who** receives those permissions. It connects a `Role` to subjects (such as `Users`, `Groups`, or `ServiceAccounts`) within that namespace.  
*(Analogy: A `Role` is a job description with permissions; a `RoleBinding` is the employment contract assigning that job to an individual.)*

---

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?
**Answer:**  
The developer service account (`dev-user`) failed to access `prod` because the `RoleBinding` (`dev-user-binding`) and associated `Role` (`pod-reader`) were explicitly scoped within the `dev` namespace. In Kubernetes, RBAC permissions are namespace-scoped by default, and access across namespace boundaries is prohibited unless an explicit `RoleBinding` in `prod` or a cluster-wide `ClusterRoleBinding` exists.  
- **Security Principles Demonstrated:**  
  1. **Namespace Isolation / Multi-Tenancy Segregation:** Separating production workloads from non-production environments to prevent accidental modification or unauthorized reconnaissance.
  2. **Default Deny (Implicit Deny):** All actions not explicitly permitted by an RBAC rule are blocked by default.

---

## 7. Verification Artifacts & RBAC Manifest

To prove that the cluster RBAC configuration is active and correctly structured, the YAML manifest of the `RoleBinding` is extracted:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

### Verified Manifest (`dev-user-binding.yaml`):
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-user-binding
  namespace: dev
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Corresponding Role Definition (`pod-reader.yaml`):
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

---

## 8. Security Best-Practices Checklist

| Security Control | Status | Evidence / Verification Method |
| :--- | :---: | :--- |
| **Root user not used for daily operational tasks** | [x] PASSED | Verified creation of dedicated `CloudAdmin_Haqiem` user. Root identity discarded after bootstrap. |
| **Permissions granted via groups/roles, not directly to users** | [x] PASSED | Created `Admins` group with `AdministratorAccess` policy; attached `CloudAdmin_Haqiem` as member. |
| **Least-privilege (read-only) identity created & verified** | [x] PASSED | Created `Analyst_Fauzi` with `AmazonS3ReadOnlyAccess` policy only. |
| **Access key lifecycle & rotation demonstrated** | [x] PASSED | Generated programmatic access keys and demonstrated deactivation (`Inactive` status). |
| **Kubernetes RBAC enforces boundary isolation** | [x] PASSED | Verified using `kubectl auth can-i`: cross-namespace access to `prod` and write operations in `dev` both returned `no`. |

---

## 9. Cleanup & Teardown

To ensure complete resource reclamation and remove all local test infrastructure, execute the following teardown commands:

```bash
# 1. Delete the local Kubernetes KinD cluster
kind delete cluster --name ccse-lab1

# 2. Stop and remove the LocalStack container
docker stop localstack
docker rm localstack

# 3. Clean local AWS CLI temporary environment variables
unset EP
```

---

## 10. Conclusion & Advanced Security Considerations

### 10.1 Key Takeaways
1. **Identity as the Primary Perimeter:** In modern cloud-native architectures, network perimeters alone are insufficient. Fine-grained identity and access management constitutes the first and most critical defense layer.
2. **Platform-Level Enforcement:** While IAM policies define authorization intent, platforms like Kubernetes RBAC enforce real-time boundary verification on every API invocation.
3. **Defense-in-Depth:** Combining least-privilege scoping, group-based assignment, credential rotation, and namespace segregation ensures that a failure at one layer does not compromise the broader cloud estate.

### 10.2 Future Hardening & Policy-as-Code Extensions
- **Infrastructure as Code (IaC):** Manage all IAM roles, groups, and Kubernetes RBAC bindings reproducibly using Terraform or OpenTofu.
- **Conditional IAM Policies:** Implement context-aware IAM conditions requiring Multi-Factor Authentication (`aws:MultiFactorAuthPresent: true`) and restricting access to specific source IP ranges (`aws:SourceIp`).
- **Policy-as-Code Guardrails:** Deploy Open Policy Agent (OPA) Gatekeeper or Kyverno within Kubernetes to prevent privilege escalation (e.g., blocking pods from running as root `runAsNonRoot: true`).

---
*Report completed and verified against lab requirements for IKB42603 Cloud Computing Security Essentials.*
