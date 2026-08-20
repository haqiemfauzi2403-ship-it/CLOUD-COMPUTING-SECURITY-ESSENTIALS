# Lab 1: Cloud Account Security, Identity & Access Management (IAM & RBAC)
**Student Name:** Muhammad Haqiem Bin Mohd Fauzi(`CloudAdmin_Haqiem` / `Analyst_Fauzi`) 
**Student ID:** 52215225398
**Course Code:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Lecturer name:** Miss Adani
**Environment:** Kali Linux 2026.1 (VMware), Docker Engine 28.5.2, LocalStack (AWS Simulator), KinD v1.35.0 (Kubernetes-in-Docker), Kubectl, AWS CLI v2  

---

## Table of Contents
1. [Executive Summary & Learning Outcomes](#1-executive-summary--learning-outcomes)
2. [Technical Prerequisites & Lab Architecture](#2-technical-prerequisites--lab-architecture)
3. [Session A (Week 1) — Cloud Identity Governance with LocalStack IAM](#3-session-a-week-1--cloud-identity-governance-with-localstack-iam)
   - [3.1 Environment Setup & LocalStack Health Verification](#31-environment-setup--localstack-health-verification)
   - [3.2 Task 1 — Mapping the Cloud Identity Landscape](#32-task-1--mapping-the-cloud-identity-landscape)
   - [3.3 Task 2 — Creating a Least-Privilege Admin Group & Identity](#33-task-2--creating-a-least-privilege-admin-group--identity)
   - [3.4 Task 3 — Enforcing Least Privilege with Scoped Policies](#34-task-3--enforcing-least-privilege-with-scoped-policies)
   - [3.5 Task 4 — Credential Hygiene & Access Key Lifecycle Management](#35-task-4--credential-hygiene--access-key-lifecycle-management)
4. [Session B (Week 2) — Enforced Access Control with Kubernetes RBAC](#4-session-b-week-2--enforced-access-control-with-kubernetes-rbac)
   - [4.1 Local Kubernetes Cluster Deployment (KinD)](#41-local-kubernetes-cluster-deployment-kind)
   - [4.2 Task 5 — Environment Isolation via Namespaces](#42-task-5--environment-isolation-via-namespaces)
   - [4.3 Task 6 — Defining Least-Privilege Role & RoleBinding](#43-task-6--defining-least-privilege-role--rolebinding)
   - [4.4 Task 7 — Proving the Authorization Boundary](#44-task-7--proving-the-authorization-boundary)
   - [4.5 RBAC YAML Manifest Verification](#45-rbac-yaml-manifest-verification)
5. [Deliverables & Assessment Short-Answer Questions](#5-deliverables--assessment-short-answer-questions)
6. [Security Best-Practices Checklist](#6-security-best-practices-checklist)
7. [System Teardown & Resource Cleanup](#7-system-teardown--resource-cleanup)
8. [Conclusion & References](#8-conclusion--references)

---

## 1. Executive Summary & Learning Outcomes

In modern cloud computing and containerized orchestrations, **Identity and Access Management (IAM)** and **Role-Based Access Control (RBAC)** serve as the foundational security perimeter. This lab demonstrates practical implementations of zero-trust architecture, identity governance, least-privilege enforcement, and credential lifecycle hygiene across two core paradigms:
1. **Cloud Service Provider IAM (LocalStack/AWS IAM simulation):** Transitioning away from root account usage, implementing group-based policy inheritance, configuring fine-grained read-only permissions, and practicing programmatic credential rotation.
2. **Container Orchestration Engine RBAC (Kubernetes RBAC via KinD):** Implementing namespace isolation, service account creation, granular role definitions (`verbs` and `resources`), role binding, and evaluating runtime authorization decisions (`kubectl auth can-i`).

### Course & Skill Mapping
- **Course Learning Outcome (CLO2):** Construct secure cloud operations that safeguard data integrity.
- **Skill & Value Clusters:** VBE3 (Integrity) and SC8 (Integrated Problem-Solving).

---

## 2. Technical Prerequisites & Lab Architecture

The lab is conducted in an isolated offline-capable environment on Kali Linux within VMware Workstation.

```
+-------------------------------------------------------------------------------+
|                             Host: Kali Linux VM                               |
|                                                                               |
|  +-------------------------------------+  +--------------------------------+  |
|  |       LocalStack (Docker)           |  |      KinD Kubernetes Node      |  |
|  |  - Endpoint: http://localhost:4566  |  |  - Control Plane v1.35.0       |  |
|  |  - Emulated Services: IAM, STS, S3  |  |  - Namespaces: dev, prod       |  |
|  |  - Identities: CloudAdmin, Analyst  |  |  - ServiceAccount: dev-user   |  |
|  +-------------------------------------+  +--------------------------------+  |
|                     ^                                      ^                  |
|                     | AWS CLI v2                           | Kubectl CLI      |
|                     +------------------+-------------------+                  |
|                                        |                                      |
|                                [ Terminal Session ]                           |
+-------------------------------------------------------------------------------+
```

---

## 3. Session A (Week 1) — Cloud Identity Governance with LocalStack IAM

### 3.1 Environment Setup & LocalStack Health Verification

#### Step 1: Verify Docker Engine
The host container engine must be functional before provisioning cloud services.

```bash
docker --version
```

**Output:**
```
Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed
```

![01_Setup_Docker_Version](./Evidence_Lab1/01_Setup_Docker_Version.png)

---

#### Step 2 & 3: Deploy LocalStack Container & Check Health Status
LocalStack provides fully functional local emulations of AWS core APIs. The container is spawned and queried for operational health.

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack
curl http://localhost:4566/_localstack/health
```

**Health Check JSON Response:**
```json
{
  "features": { "persistence": "disabled" },
  "services": {
    "account": "available", "iam": "available", "s3": "available", "sts": "available", ...
  },
  "edition": "pro",
  "version": "2026.7.1"
}
```

![02_Setup_LocalStack_Health](./Evidence_Lab1/02_Setup_LocalStack_Health.png)

---

#### Step 4: Configure LocalStack AWS CLI Credentials & Verify Operating Caller Identity
AWS CLI was pointed to LocalStack by passing the dummy credentials and querying Security Token Service (STS).

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

**Output:**
```json
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

> **Security Analysis:** The output shows that the initial default operating identity is the AWS **Root User** (`arn:aws:iam::000000000000:root`). Operating as root represents a severe security liability due to unrestricted access across all cloud infrastructure.

![03_Mandatory_Caller_Identity](./Evidence_Lab1/03_Mandatory_Caller_Identity.png)

---

### 3.2 Task 1 — Mapping the Cloud Identity Landscape

Understanding the distinctions among core cloud identity concepts is critical for constructing robust authorization boundaries:

| Concept | AWS Term | Purpose (Student Definition) |
| :--- | :--- | :--- |
| **All-powerful owner** | **Root user** | The foundational identity created when the cloud account is established. Has complete, unrestricted access to all resources, billing, and configurations. It must never be used for day-to-day operations and should be secured with MFA and locked away. |
| **Human/app identity** | **IAM User** | A persistent, named identity entity representing a specific individual or long-running application requiring interactive console access or static programmatic keys within the cloud environment. |
| **Permission bundle** | **IAM Policy** | A formal JSON document explicitly stating authorization rules (`Effect`: Allow/Deny, `Action`, `Resource`, `Condition`) that dictate what actions an attached identity can or cannot execute. |
| **Collection of users** | **IAM Group** | A logical administrative collection of IAM users used to apply policies collectively according to job role (Role-Based Access), preventing permission drift and simplifying audits. |
| **Temporary identity** | **IAM Role** | A dynamically assumable identity granting temporary, short-lived security credentials (via STS) to users, workloads, or cross-account principals without requiring hardcoded static secrets. |

---

### 3.3 Task 2 — Creating a Least-Privilege Admin Group & Identity

To enforce separation of duties and discontinue the daily usage of the root user, a dedicated administrator group (`Admins`) was created, mapped to AWS managed administrator privileges, and populated with a named administrative identity (`CloudAdmin_Haqiem`).

```bash
EP='--endpoint-url=http://localhost:4566'

# 2.1 Create group and attach AdministratorAccess policy
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

![04_Task2_Create_Admins_Group](./Evidence_Lab1/04_Task2_Create_Admins_Group.png)

```bash
# 2.2 Create personal admin user
aws $EP iam create-user --user-name CloudAdmin_Haqiem

# 2.3 Put the user in the group
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_Haqiem

# 2.4 Verify group membership
aws $EP iam get-group --group-name Admins
```

**Verification Output:**
```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_Haqiem",
            "UserId": "AIDAQAAAAAAAH3UD4ZYRZ",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_Haqiem",
            "CreateDate": "2026-08-19T14:14:21.764551+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AGPAQAAAAAAAKPQOV636G",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-19T14:06:48.790064+00:00"
    }
}
```

> **Security Best Practice:** Permissions flow downstream from the `Admins` group to `CloudAdmin_Haqiem`. Attaching policies to groups rather than directly to users ensures centralized auditability, prevents permission creep, and enables swift access revocation when offboarding personnel.

![05_Mandatory_Get_Group_Admins](./Evidence_Lab1/05_Mandatory_Get_Group_Admins.png)

---

### 3.4 Task 3 — Enforcing Least Privilege with Scoped Policies

Fine-grained authorization was established by creating a specialized data analyst account (`Analyst_Fauzi`) strictly limited to S3 read operations.

```bash
# 3.1 Create read-only user
aws $EP iam create-user --user-name Analyst_Fauzi

# 3.2 Attach scoped read-only policy (AmazonS3ReadOnlyAccess)
aws $EP iam attach-user-policy --user-name Analyst_Fauzi \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 3.3 Verify attached user policies
aws $EP iam list-attached-user-policies --user-name Analyst_Fauzi
```

**Verification Output:**
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

![06_Mandatory_List_Attached_Policies](./Evidence_Lab1/06_Mandatory_List_Attached_Policies.png)

> **Blast-Radius Analysis:** By restricting `Analyst_Fauzi` exclusively to `AmazonS3ReadOnlyAccess`, the security **blast radius** is substantially minimized. If an adversary compromises these credentials, they cannot modify data, delete buckets, spawn EC2 instances for cryptojacking, alter IAM configurations, or escalate their privileges. Damage is strictly confined to read access on authorized S3 objects.

---

### 3.5 Task 4 — Credential Hygiene & Access Key Lifecycle Management

Programmatic access keys represent persistent shared secrets. Secure lifecycle management requires regular creation, monitoring, and deactivation/rotation.

#### Step 4.1: Generate Initial Access Key
```bash
aws $EP iam create-access-key --user-name Analyst_Fauzi
```

**Key Details Generated:**
- **AccessKeyId:** `LKIAQAAAAAAAFAJZV7GE`
- **Status:** `Active`

![07_Task4_Create_Access_Key](./Evidence_Lab1/07_Task4_Create_Access_Key.png)

---

#### Step 4.2: List and Audit Active Access Keys
```bash
aws $EP iam list-access-keys --user-name Analyst_Fauzi
```

![08_Task4_List_Access_Keys](./Evidence_Lab1/08_Task4_List_Access_Keys.png)

---

#### Step 4.3: Perform Key Rotation & Deactivation
A secondary key was created (`LKIAQAAAAAAAHXYJO3BF`) during rotation, and subsequently deactivated to demonstrate invalidation of compromised or stale keys.

```bash
# Deactivate the key
aws $EP iam update-access-key --user-name Analyst_Fauzi \
    --access-key-id LKIAQAAAAAAAHXYJO3BF --status Inactive

# Verify updated status
aws $EP iam list-access-keys --user-name Analyst_Fauzi
```

**Key Status Audit Output:**
```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_Fauzi",
            "AccessKeyId": "LKIAQAAAAAAAFAJZV7GE",
            "Status": "Active",
            "CreateDate": "2026-08-19T15:08:48.188310+00:00"
        },
        {
            "UserName": "Analyst_Fauzi",
            "AccessKeyId": "LKIAQAAAAAAAHXYJO3BF",
            "Status": "Inactive",
            "CreateDate": "2026-08-19T15:56:03.701680+00:00"
        }
    ]
}
```

![09_Task4_Deactivate_Access_Key](./Evidence_Lab1/09_Task4_Deactivate_Access_Key.png)

---

## 4. Session B (Week 2) — Enforced Access Control with Kubernetes RBAC

### 4.1 Local Kubernetes Cluster Deployment (KinD)

While LocalStack IAM simulates cloud governance, Kubernetes RBAC provides hard real-time kernel-level API authorization enforcement.

```bash
# Deploy throwaway cluster
kind create cluster --name ccse-lab1

# Verify cluster connectivity and control plane readiness
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

**Cluster Status:**
```
Kubernetes control plane is running at https://127.0.0.1:34403
CoreDNS is running at https://127.0.0.1:34403/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

NAME                      STATUS   ROLES           AGE   VERSION
ccse-lab1-control-plane   Ready    control-plane   51s   v1.35.0
```

![10_Setup_Kind_Cluster](./Evidence_Lab1/10_Setup_Kind_Cluster.png)

---

### 4.2 Task 5 — Environment Isolation via Namespaces

Namespaces provide logical boundaries within a shared Kubernetes cluster to prevent resource interference and enforce isolation between Development and Production tiers.

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

**Namespace Listing:**
```
NAME                 STATUS   AGE
default              Active   4m47s
dev                  Active   36s
kube-node-lease      Active   4m47s
kube-public          Active   4m47s
kube-system          Active   4m47s
local-path-storage   Active   4m36s
prod                 Active   23s
```

![11_Task5_Create_Namespaces](./Evidence_Lab1/11_Task5_Create_Namespaces.png)

---

### 4.3 Task 6 — Defining Least-Privilege Role & RoleBinding

To establish least privilege for software developers:
1. A **ServiceAccount** (`dev-user`) was created inside the `dev` namespace.
2. A **Role** (`pod-reader`) was declared restricting actions to read-only verbs (`get`, `list`, `watch`) solely on `pods` in `dev`.
3. A **RoleBinding** (`dev-user-binding`) connected the identity to the permissions.

```bash
# 6.1 Create Service Account
kubectl create serviceaccount dev-user -n dev

# 6.2 Create Role with specific verbs and resources
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods

# 6.3 Bind the Role to the Service Account
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

![12_Task6_Create_Role_Binding](./Evidence_Lab1/12_Task6_Create_Role_Binding.png)

---

### 4.4 Task 7 — Proving the Authorization Boundary

The access boundary was verified using `kubectl auth can-i` by impersonating the service account `system:serviceaccount:dev:dev-user`.

```bash
SA=system:serviceaccount:dev:dev-user

# Test 1: List pods in dev (Allowed verb in bound namespace)
kubectl auth can-i list pods -n dev --as=$SA
# Output: yes

# Test 2: Delete pods in dev (Forbidden verb in bound namespace)
kubectl auth can-i delete pods -n dev --as=$SA
# Output: no

# Test 3: List pods in prod (Target outside RoleBinding scope)
kubectl auth can-i list pods -n prod --as=$SA
# Output: no
```

![13_Mandatory_Kubernetes_RBAC_Test](./Evidence_Lab1/13_Mandatory_Kubernetes_RBAC_Test.png)

#### In-Depth Security Explanation: Authentication vs. Authorization
- **Authentication (AuthN - *Who are you?*):** The Kubernetes API server successfully authenticates `system:serviceaccount:dev:dev-user` in all three test queries. The request principal is valid and recognized.
- **Authorization (AuthZ - *What are you allowed to do?*):**
  - **Test 1 (`list pods -n dev`) -> `yes`:** The request passes authorization because `dev-user-binding` maps `dev-user` to the `pod-reader` role which explicitly allows the verb `list` on `pods` within namespace `dev`.
  - **Test 2 (`delete pods -n dev`) -> `no`:** The request is blocked at authorization because `pod-reader` only grants `get,list,watch`. Kubernetes enforces a default-deny model; verbs not explicitly declared are rejected.
  - **Test 3 (`list pods -n prod`) -> `no`:** The request is blocked at authorization because `dev-user-binding` is a namespaced `RoleBinding` scoped strictly to `dev`. It has zero jurisdiction over the `prod` namespace.

---

### 4.5 RBAC YAML Manifest Verification

The underlying state of the RBAC binding was inspected via YAML output:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

**YAML Manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-19T16:45:44Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "1279"
  uid: a4fd68ab-0e3f-4298-93cd-04199c2533cc
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

![14_Task7_YAML_Verification](./Evidence_Lab1/14_Task7_YAML_Verification.png)

---

## 5. Deliverables & Assessment Short-Answer Questions

### Q1: Why is attaching policies to groups better than attaching them directly to users?
> **Answer:** Attaching policies to groups promotes centralized governance, reduces human error, and prevents **permission drift**. In an enterprise environment with hundreds of users:
> 1. **Scalability:** When job responsibilities change or a new tool is introduced, administrators modify the single group policy once, automatically updating permissions for all members.
> 2. **Auditability & Consistency:** Group-based assignment ensures that all employees in a given role (e.g., developers, auditors) maintain uniform, standard baseline permissions without orphan policies attached directly to individual user accounts.
> 3. **Simplified Lifecycle Management:** When an employee transfers departments or leaves the organization, removing them from the group instantly revokes all associated privileges.

---

### Q2: What is the difference between an IAM User and an IAM Role?
> **Answer:**
> - **IAM User:** A permanent identity designed for a specific human or system that requires long-term identity credentials (username/password for AWS Console access, or static long-lived Access Key ID & Secret Access Key for CLI/API access).
> - **IAM Role:** A dynamic identity that does not have long-term credentials associated with it. Instead, trusted entities (such as EC2 instances, Lambda functions, or external federated users) dynamically **assume** the role via AWS STS to receive temporary, expiring security tokens. Roles eliminate the risk of hardcoded credentials.

---

### Q3: Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
> **Answer:** The principle of **Least Privilege** dictates that an identity should only be granted the absolute minimum permissions required to perform its authorized duties, and nothing more.
> In our implementation, the `Analyst_Fauzi` account was granted only `AmazonS3ReadOnlyAccess`. If this account's credentials are stolen:
> - The attacker **cannot** delete S3 data (safeguarding data integrity).
> - The attacker **cannot** launch compute instances or modify VPCs (safeguarding availability and financial cost).
> - The attacker **cannot** alter IAM policies or create admin users (preventing privilege escalation).
> The **blast radius** (extent of damage possible) is confined strictly to reading public/permitted S3 bucket contents rather than catastrophic full-infrastructure takeover.

---

### Q4: In Kubernetes, what is the difference between a Role and a RoleBinding?
> **Answer:**
> - **Role:** An RBAC resource that defines **what** actions are permitted. It contains a collection of permission rules specifying API groups, target resources (e.g., `pods`, `services`), and allowed operations/verbs (e.g., `get`, `list`, `watch`). A `Role` does not define *who* gets these permissions.
> - **RoleBinding:** An RBAC resource that defines **who** receives the permissions. It binds a `Role` (or `ClusterRole`) to one or more subjects (such as `ServiceAccount`, `User`, or `Group`) within a specific namespace. Without a `RoleBinding`, a `Role` remains unassigned and inert.

---

### Q5: Why did the developer service account fail to access prod, and which security principle does that demonstrate?
> **Answer:** The service account `dev-user` failed to access `prod` because its permissions were granted via a namespaced `RoleBinding` (`dev-user-binding`) scoped strictly to the `dev` namespace. In Kubernetes:
> 1. Namespaced roles and bindings cannot cross namespace boundaries.
> 2. No RoleBinding existed linking `dev-user` to any role inside `prod`.
> 3. Kubernetes enforces a default **closed/deny-by-default** security posture.
> 
> This demonstrates the security principle of **Multi-Tenancy Isolation / Compartmentalization** and **Least Privilege**, ensuring that compromised or unauthorized identities in non-production tiers cannot view, tamper with, or compromise production workloads.

---

## 6. Security Best-Practices Checklist

| Status | Security Best Practice Item | Verification in Lab |
| :---: | :--- | :--- |
| :white_check_mark: | **Root user is not used for daily tasks** | Verified: Default root caller identity audited (`03_Mandatory_Caller_Identity.png`); dedicated admin group `Admins` and user `CloudAdmin_Haqiem` created. |
| :white_check_mark: | **Permissions granted via groups/roles, not directly to individuals** | Verified: `AdministratorAccess` attached to `Admins` group; `CloudAdmin_Haqiem` assigned via group membership (`05_Mandatory_Get_Group_Admins.png`). |
| :white_check_mark: | **At least one least-privilege (read-only) identity created and tested** | Verified: `Analyst_Fauzi` created with restricted `AmazonS3ReadOnlyAccess` policy (`06_Mandatory_List_Attached_Policies.png`). |
| :white_check_mark: | **Access keys listed and rotation (deactivation) demonstrated** | Verified: Access keys listed and secondary key deactivated (`Status: Inactive`) (`09_Task4_Deactivate_Access_Key.png`). |
| :white_check_mark: | **Kubernetes RBAC blocks unauthorized actions (delete / cross-namespace)** | Verified: `kubectl auth can-i` blocked `delete pods` in `dev` and blocked all access to `prod` (`13_Mandatory_Kubernetes_RBAC_Test.png`). |

---

## 7. System Teardown & Resource Cleanup

To uphold infrastructure hygiene and ensure zero lingering compute or storage resources after completing the laboratory exercises, all local clusters and containers were terminated.

```bash
# 1. Delete the KinD Kubernetes cluster
kind delete cluster --name ccse-lab1

# 2. Stop and remove the LocalStack container
docker stop localstack && docker rm localstack
```

**Cleanup Output:**
```
Deleting cluster "ccse-lab1" ...
Deleted nodes: ["ccse-lab1-control-plane"]
localstack
```

![15_System_Cleanup](./Evidence_Lab1/15_System_Cleanup.png)

---

## 8. Conclusion & References

By completing this hands-on lab, we successfully established and audited end-to-end identity governance and access control mechanisms across simulated cloud infrastructure (LocalStack IAM) and production container orchestration (Kubernetes RBAC). We demonstrated that enforcing the principle of least privilege, segmenting environments through namespaces, and practicing proactive credential lifecycle management drastically minimizes attack surfaces and mitigates organizational risk.

### References
- **Course Lectures:** IKB42603 Weeks 1–2 (Fundamentals, Security Architecture), Weeks 5 & 7 (Access Control, Identity Management).
- **LocalStack Documentation:** [docs.localstack.cloud](https://docs.localstack.cloud)
- **Kubernetes RBAC Official Guide:** [kubernetes.io/docs/reference/access-authn-authz/rbac/](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- **Cloud Security Alliance (CSA) Security Guidance v5:** Domain on Identity & Access Management.
- **AWS Identity and Access Management (IAM) Best Practices:** AWS Security Documentation.
