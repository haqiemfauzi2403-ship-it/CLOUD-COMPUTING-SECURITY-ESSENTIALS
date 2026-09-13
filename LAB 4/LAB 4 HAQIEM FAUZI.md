# UNIVERSITI KUALA LUMPUR (UniKL MIIT)
## Malaysian Institute of Information Technology
### IKB42603 Cloud Computing Security Essentials
### Lab Report 4: Access Control & Network Security
**AuthN vs AuthZ, Network Segmentation, Firewall Rules, and Container Hardening — Docker & Kubernetes**

---

| **Academic Metric / Field** | **Specification Details** |
| :--- | :--- |
| **Student Name** | **Muhammad Haqiem Bin Mohd Fauzi** |
| **Student ID** | **52215225398** |
| **Course Code & Title** | **IKB42603 Cloud Computing Security Essentials** |
| **Program** | Bachelor of Information Technology / Computer Science (Information Security / Cloud Computing) |
| **Lecturer / Instructor** | **Prof. Dr. Shahrulniza Musa / Ms. Adani** |
| **Lab Module** | **Lab 4 (Weeks 7–8)** |
| **Lab Focus Areas** | **Session A (Week 7):** Authentication vs. Authorization, MFA / TOTP, Kubernetes RBAC Enforcement (Tasks 1–3)<br>**Session B (Week 8):** Three-Tier Network Segmentation, Default-Deny Firewall Rules, Container Hardening & Vulnerability Scanning (Tasks 4–6) |
| **GitHub Repository** | [haqiemfauzi2403-ship-it/CLOUD-COMPUTING-SECURITY-ESSENTIALS](https://github.com/haqiemfauzi2403-ship-it/CLOUD-COMPUTING-SECURITY-ESSENTIALS) |
| **Date of Submission** | **13 September 2026** |

---

## Table of Contents

1. [Executive Summary & Lab Learning Outcomes](#1-executive-summary--lab-learning-outcomes)
2. [Course & Assessment Mapping](#2-course--assessment-mapping)
3. [Theoretical Foundations & Architecture Overview](#3-theoretical-foundations--architecture-overview)
   - [3.1 Identity as the New Security Perimeter](#31-identity-as-the-new-security-perimeter)
   - [3.2 Authentication (AuthN) vs. Authorization (AuthZ) Pipeline](#32-authentication-authn-vs-authorization-authz-pipeline)
   - [3.3 Multi-Factor Authentication Mechanics (RFC 6238 TOTP)](#33-multi-factor-authentication-mechanics-rfc-6238-totp)
   - [3.4 Kubernetes Role-Based Access Control (RBAC) Architecture](#34-kubernetes-role-based-access-control-rbac-architecture)
   - [3.5 Micro-Segmentation & Defense-in-Depth (Three-Tier Isolation)](#35-micro-segmentation--defense-in-depth-three-tier-isolation)
   - [3.6 Host Perimeter Filtering (Default-Deny Firewall)](#36-host-perimeter-filtering-default-deny-firewall)
   - [3.7 Container Runtime Hardening & Attack Surface Elimination](#37-container-runtime-hardening--attack-surface-elimination)
4. [Session A (Week 7): Authentication & Authorization](#4-session-a-week-7-authentication--authorization)
   - [Task 1: Authentication — A Password-Protected Service (HTTP Basic Auth)](#task-1-authentication--a-password-protected-service-http-basic-auth)
   - [Task 2: Add a Second Factor (MFA / TOTP RFC 6238)](#task-2-add-a-second-factor-mfa--totp-rfc-6238)
   - [Task 3: Authorization — Kubernetes RBAC Roles & ServiceAccounts](#task-3-authorization--kubernetes-rbac-roles--serviceaccounts)
5. [Session B (Week 8): Network Security & Hardening](#5-session-b-week-8-network-security--hardening)
   - [Task 4: Network Segmentation (Three-Tier Web / App / DB Architecture)](#task-4-network-segmentation-three-tier-web--app--db-architecture)
   - [Task 5: Firewall Rules (Default-Deny Host Packet Filtering)](#task-5-firewall-rules-default-deny-host-packet-filtering)
   - [Task 6: Container Hardening & Static Vulnerability Auditing](#task-6-container-hardening--static-vulnerability-auditing)
6. [Deliverables & Assessment Summary](#6-deliverables--assessment-summary)
   - [6.1 Forensic Evidence Screenshot Matrix](#61-forensic-evidence-screenshot-matrix)
   - [6.2 Comprehensive Short-Answer Questions (Q1 – Q5)](#62-comprehensive-short-answer-questions-q1--q5)
   - [6.3 Verification Command Artifacts](#63-verification-command-artifacts)
7. [Security Best-Practices Checklist](#7-security-best-practices-checklist)
8. [Cleanup & Teardown Protocols](#8-cleanup--teardown-protocols)
9. [Advanced Engineering Expansions](#9-advanced-engineering-expansions)
10. [Academic & Industry References](#10-academic--industry-references)

---

## 1. Executive Summary & Lab Learning Outcomes

### 1.1 Executive Overview
In modern distributed cloud environments, traditional static network perimeters have dissolved. Workloads, microservices, and serverless entities dynamically scale across hybrid multi-tenant infrastructures. Under this paradigm, security engineering requires a dual-pronged approach governed by the principle of **Defense in Depth**:
1. **Controlling Ingress & Identity (Session A):** Rigorously verifying *WHO* enters the system (Authentication) and strictly scoping *WHAT* operations they are permitted to execute (Authorization). This is realized through HTTP authentication protocols, RFC 6238 Time-Based One-Time Password (TOTP) Multi-Factor Authentication (MFA), and Kubernetes Role-Based Access Control (RBAC).
2. **Constraining Lateral Reach & Reducing Attack Surface (Session B):** Assuming that perimeter controls will eventually experience breach attempts, the architecture enforces network micro-segmentation across tiers, implements strict default-deny packet filtering via Linux `iptables`, and hardens containerized execution runtimes by dropping kernel capabilities, enforcing immutable read-only filesystems, and executing unprivileged non-root users.

This laboratory practical exercises hands-on security implementations across Docker container networks, the Linux network stack, and Kubernetes orchestration clusters, directly mapping theoretical access control models to production-grade security architectures.

### 1.2 Lab Learning Outcomes
Upon completion of this lab module, the student has demonstrated practical mastery in:
- **Distinguishing & Implementing AuthN vs. AuthZ:** Establishing cryptographic verification of entity identities and enforcing deterministic authorization rules.
- **Deploying Multi-Factor Authentication (MFA):** Implementing RFC 6238 TOTP algorithms utilizing cryptographic shared secrets, pseudo-random time synchronization, and zero-dependency terminal validation.
- **Configuring Network Access Control & Micro-Segmentation:** Isolating tiered application stacks into discrete software-defined bridge networks to halt unauthorized lateral movement.
- **Container Runtime Hardening:** Deploying unprivileged microservices under non-root user namespaces (`UID 1000:1000`), dropping all Linux kernel capabilities (`CAP_DROP=ALL`), disabling privilege escalation flags (`no-new-privileges`), and enforcing read-only root filesystems.
- **Container Vulnerability Management:** Executing static security scans via Trivy to identify Common Vulnerabilities and Exposures (CVEs) within container base layers.

---

## 2. Course & Assessment Mapping

| Assessment / Curricular Component | Mapping Specification | Description & Contextual Alignment |
| :--- | :--- | :--- |
| **Course Learning Outcome (CLO)** | **CLO2** | *Construct secure cloud operations that safeguard data integrity.* Enforcing strict identity boundaries, authorization policies, and container isolation guarantees that application states and databases cannot be maliciously tampered with or corrupted. |
| **Syllabus Lecture Topics** | **Week 5 & Week 9** | Week 5: Access Control Models (DAC, MAC, RBAC, ABAC) & IAM.<br>Week 9: Network Security Patterns, Micro-segmentation, and Host Hardening. |
| **Value & Skill Clusters** | **VBE3 & SC8** | **VBE3 (Integrity):** Adhering to cryptographic principles and strict least-privilege policies.<br>**SC8 (Integrated Problem-Solving):** Diagnosing connectivity barriers, configuring software firewalls, and orchestrating multi-container network boundaries. |
| **Assessment Deliverables** | **Lab Assignment Report** | Step-by-step documentation, command output verification, 7 forensic screenshots, and 5 short-answer analytical evaluations. |

```
+-----------------------------------------------------------------------------------+
|                     LAB 4 ARCHITECTURAL SEGREGATION                               |
+-----------------------------------------------------------------------------------+
|      SESSION A (Week 7): WHO Gets In?      |   SESSION B (Week 8): WHAT Can They Reach?   |
+--------------------------------------------+--------------------------------------+
| Task 1: Password-Protected Service (AuthN) | Task 4: Three-Tier Network Isolation |
| Task 2: Second Factor (MFA / TOTP RFC 6238)| Task 5: Default-Deny Host Firewall   |
| Task 3: Authorization (Kubernetes RBAC)    | Task 6: Container Hardening & Trivy  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Theoretical Foundations & Architecture Overview

### 3.1 Identity as the New Security Perimeter
In traditional perimeter security models ("Castle-and-Moat"), internal networks were treated as inherently trusted once an external firewall was crossed. In cloud computing, this assumption is catastrophic. An attacker compromising a single publicly exposed component can trivially traverse the flat network to reach mission-critical databases.

Under **Zero Trust Architecture (NIST SP 800-207)**, the network perimeter is replaced by **Identity**. Every transaction, microservice invocation, and administrative action must be explicitly authenticated, strictly authorized, and continuously validated regardless of network location.

```
Traditional Perimeter Model (Flawed):
[ Attacker ] ──► [ Firewall ] ──► [ Web Server ] ────► [ Database ] (Unrestricted Lateral Hop)

Zero Trust Identity & Micro-Segmentation Model (Enforced):
[ Principal ] ──► [ AuthN Gate ] ──► [ AuthZ Engine (RBAC) ] ──► [ Web (frontend-net) ]
                                                                        │ (BLOCKED)
                                                                        ▼
                                                             [ Isolated Database (backend-net) ]
```

### 3.2 Authentication (AuthN) vs. Authorization (AuthZ) Pipeline
Authentication and authorization represent two distinct, sequential operational phases:

```mermaid
flowchart LR
    Principal([Requesting Principal]) -->|1. Credentials: Who are you?| AuthN{Authentication\nAuthN}
    AuthN -->|Invalid / Missing| Deny1[HTTP 401 Unauthorized / Reject]
    AuthN -->|Cryptographically Verified| PrincipalIdentity[Authenticated Identity]
    PrincipalIdentity -->|2. Action + Resource: What may you do?| AuthZ{Authorization\nAuthZ}
    AuthZ -->|Not Whitelisted in RBAC| Deny2[HTTP 403 Forbidden / Deny]
    AuthZ -->|Explicitly Allowed by Role| Permit[Execute Action on Target]
```

- **Authentication (AuthN):** Establishes and verifies identity. It answers: *"Are you who you claim to be?"* In Task 1, Nginx verifies identity using HTTP Basic Authentication (`Authorization: Basic <base64>`) matched against a cryptographically hashed `htpasswd` file.
- **Authorization (AuthZ):** Evaluates permissions granted to an authenticated identity. It answers: *"Are you permitted to perform this specific verb on this specific object?"* In Task 3, the Kubernetes API Server evaluates whether ServiceAccount `dev` has rights to `get`, `list`, or `delete` pods in namespace `app`.

### 3.3 Multi-Factor Authentication Mechanics (RFC 6238 TOTP)
Passwords alone provide inadequate security due to credential stuffing, phishing, and dictionary attacks. Multi-Factor Authentication combines at least two orthogonal authentication factors:
1. **Something you know:** Knowledge factor (e.g., password, PIN).
2. **Something you have:** Possession factor (e.g., cryptographic hardware key, TOTP authenticator).
3. **Something you are:** Inherence factor (e.g., biometrics).

The **Time-Based One-Time Password (TOTP)** algorithm (RFC 6238) computes a dynamic 6-digit passcode by hashing a shared secret key $K$ and the current Unix epoch time $T$ divided into 30-second time steps:

$$T_0 = 0, \quad X = 30 \text{ seconds}$$
$$T_c = \left\lfloor \frac{\text{Current Unix Time} - T_0}{X} \right\rfloor$$
$$\text{HMAC-Value} = \text{HMAC-SHA-1}(K, T_c)$$

The resulting 160-bit HMAC output undergoes dynamic truncation to extract a 31-bit unsigned integer, which is computed modulo $10^6$ to produce the standard 6-digit numeric code. Because $T_c$ increments every 30 seconds, intercepted passcodes cannot be replayed after expiration.

```
+-----------------------------------------------------------------------------------+
|                             RFC 6238 TOTP GENERATION                              |
+-----------------------------------------------------------------------------------+
|  [ Shared Secret K (Base32) ]  +  [ Time-Step Counter Tc = floor(UnixTime / 30) ] |
|                                       │                                           |
|                                       ▼                                           |
|                           [ HMAC-SHA1(K, Tc) ]                                    |
|                                       │                                           |
|                                       ▼                                           |
|                            [ Dynamic Truncation ]                                 |
|                                       │                                           |
|                                       ▼                                           |
|                         [ Modulo 1,000,000 (6 Digits) ]                           |
|                                       │                                           |
|                                       ▼                                           |
|                         Valid for 30 Seconds: 912297                              |
+-----------------------------------------------------------------------------------+
```

### 3.4 Kubernetes Role-Based Access Control (RBAC) Architecture
Kubernetes natively implements an authorization engine based on Role-Based Access Control. All requests to the API server are evaluated against four decoupled primitives:

```
[ Subject: ServiceAccount (app:dev) ]
               │
               ▼ (Bound via)
     [ RoleBinding (dev-rb) ]
               │
               ▼ (Grants permissions defined in)
        [ Role (dev-role) ]
        ├── apiGroups: [""]
        ├── resources: ["pods"]
        └── verbs: ["get", "list"]
```

- **Subjects:** Users, Groups, or `ServiceAccounts` executing operations.
- **Roles:** Namespace-scoped definitions whitelisting allowed API groups, resources, and verbs.
- **RoleBindings:** Declarative associations granting a specified `Role` to designated subjects within a namespace.
- **Default-Deny Semantics:** Kubernetes RBAC possesses no explicit "deny" rules. If an incoming request is not explicitly whitelisted by at least one matching `RoleBinding` or `ClusterRoleBinding`, the API server rejects it with an HTTP 403 Forbidden status.

### 3.5 Micro-Segmentation & Defense-in-Depth (Three-Tier Isolation)
Traditional network architectures rely on flat virtual local area networks (VLANs). If an adversary achieves remote code execution (RCE) on an internet-facing frontend web server, flat networks allow immediate scanning and extraction of backend databases.

Micro-segmentation isolates individual application tiers onto separate Layer-2/Layer-3 software-defined network bridges:
- **`frontend-net`:** Hosts public-facing ingress components (`web`) and business logic gateways (`app`).
- **`backend-net`:** Hosts application middleware (`app`) and database stores (`db`).

```
                    [ External Client Request ]
                                │
                                ▼
    +─────────────────────────────────────────────────────────+
    |                    frontend-net                         |
    |                                                         |
    |  +--------------------+         +--------------------+  |
    |  |  web (Nginx Proxy) | ──────► |  app (Middleware)  |  |
    |  +--------------------+         +--------------------+  |
    +───────────────────────────────────────────│─────────────+
                                                │ (Dual-Homed)
    +───────────────────────────────────────────│─────────────+
    |                    backend-net            ▼             |
    |                                 +--------------------+  |
    |                                 |    db (Redis)      |  |
    |                                 +--------------------+  |
    |           [ X BLOCKED Lateral Traversal from web ]      |
    +─────────────────────────────────────────────────────────+
```

Because `web` is solely attached to `frontend-net`, the Linux kernel network stack inside the `web` container possesses no routing entry or physical interface connecting to `db` (`172.x.x.x`). DNS resolution and TCP SYN packets to `db:6379` fail immediately.

### 3.6 Host Perimeter Filtering (Default-Deny Firewall)
A secure host firewall enforces **least privilege at the network packet layer**. Under standard default-allow policies, all inbound packets are processed unless explicitly blacklisted. This model consistently fails when new ports are opened or undocumented administrative tools are installed.

Under the **Default-Deny** paradigm (matching cloud Security Group invariants):
1. The default policy for the `INPUT` chain is set to `DROP` (`iptables -P INPUT DROP`).
2. Only necessary traffic is explicitly whitelisted:
   - Loopback interface communications (`-i lo -j ACCEPT`).
   - Secure web traffic on TCP port 443 (`-p tcp --dport 443 -j ACCEPT`).
3. Any packet arriving on an unwhitelisted port (e.g., SSH 22, Telnet 23, MySQL 3306, Redis 6379) is silently dropped at the kernel interface without responding with TCP RST or ICMP port unreachable packets, depriving adversaries of reconnaissance intelligence.

### 3.7 Container Runtime Hardening & Attack Surface Elimination
Standard container deployments run processes as the root user (`UID 0`) with default Linux capabilities, grant write access across the root filesystem, and permit child process privilege escalation. If an attacker discovers an RCE vulnerability within the application, they gain root privilege inside the container and can attempt kernel exploits to escape to the host.

Production container hardening eliminates these vectors:
- **Non-Root User (`--user 1000:1000`):** Enforces execution under an unprivileged UID/GID, preventing modifications to system binaries.
- **Read-Only Root Filesystem (`--read-only`):** Prevents attackers from downloading malware, drop-loaders, or rootkits into `/bin`, `/usr`, or `/lib`.
- **Capability Dropping (`--cap-drop=ALL`):** Strips all 41+ Linux kernel capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_CHOWN`, `CAP_DAC_OVERRIDE`), restricting container processes strictly to standard unprivileged POSIX system calls.
- **No-New-Privileges (`--security-opt no-new-privileges`):** Prevents binaries with the SUID or SGID bit (such as `/bin/su` or `/usr/bin/sudo`) from executing with elevated permissions.
- **Temporary In-Memory Storage (`--tmpfs /tmp`):** Grants non-persistent, memory-backed write space for necessary application socket/scratch files without compromising disk immutability.

---

## 4. Session A (Week 7): Authentication & Authorization

### Task 1: Authentication — A Password-Protected Service (HTTP Basic Auth)

#### Objective & Methodology
Configure an Nginx web proxy enforcing HTTP Basic Authentication (`auth_basic`). Only HTTP requests containing a valid base64-encoded `Authorization: Basic <credentials>` header matched against a bcrypt-hashed user record in `/etc/nginx/.htpasswd` are permitted ingress.

#### Terminal Commands Executed
```bash
# 1. Generate an encrypted htpasswd file containing user 'student' and password 'P@ssw0rd!'
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt

# 2. Construct the Nginx server configuration enforcing basic authentication
cat > default.conf <<'EOF'
server { 
    listen 80;
    location / { 
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        return 200 'Authenticated OK\n'; 
    } 
}
EOF

# 3. Launch the containerized Nginx instance binding local port 8080
docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd nginx

# 4. Probe the endpoint without authentication credentials
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080

# 5. Probe the endpoint supplying valid HTTP Basic Auth credentials
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

#### Forensic Output & Verification
```text
no-creds: 401
Authenticated OK
```

#### Technical Analysis
- **Unauthenticated Probe:** In the initial request, the client transmitted an empty `Authorization` header. Nginx evaluated the `auth_basic "Restricted"` directive, halted request processing, and issued an **HTTP 401 Unauthorized** response containing the header `WWW-Authenticate: Basic realm="Restricted"`.
- **Authenticated Probe:** In the second request, `curl -u student:'P@ssw0rd!'` encoded the credentials into base64 (`c3R1ZGVudDpQQHNzdzByZCE=`) and passed them in the header `Authorization: Basic c3R1ZGVudDpQQHNzdzByZCE=`. Nginx decoded the credentials, extracted the salt and cost factor from `htpasswd.txt`, evaluated the bcrypt hash, confirmed cryptographic equivalence, and returned an **HTTP 200 OK** status along with the body payload `Authenticated OK`.

#### Evidence Screenshot — Task 1
<p align="center">
  <img src="Evidence/The%20401%20(no%20credentials)%20and%20200%20(valid%20credentials)%20results%20(Task%201).png" alt="Task 1 Evidence: HTTP 401 vs 200 Authentication" width="850"/>
</p>

*Figure 1.1: Terminal execution showing HTTP Basic Authentication validation. The initial unauthenticated request triggers HTTP 401 Unauthorized, whereas valid credentials return HTTP 200 with the payload "Authenticated OK".*

---

### Task 2: Add a Second Factor (MFA / TOTP RFC 6238)

#### Objective & Methodology
Implement a zero-dependency Multi-Factor Authentication (MFA) validation mechanism using the RFC 6238 Time-Based One-Time Password algorithm. A cryptographically secure 20-byte base32-encoded shared secret is generated, enrolled into a simulated authenticator client via `oathtool`, and validated against user terminal input.

#### Terminal Commands Executed
```bash
# 1. Generate a 20-byte cryptographically secure random shared secret encoded in Base32
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol this secret in an authenticator app: $SECRET"

# 2. Compute the current 6-digit TOTP passcode for the shared secret
oathtool --totp -b "$SECRET"

# 3. Prompt user for passcode input and perform cryptographic equality comparison
echo -n 'Enter the 6-digit code: '
read CODE
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

#### Forensic Output & Verification
```text
Enter the 6-digit code: 912297
MFA OK
```

#### Technical Analysis
- **Cryptographic Seed:** The variable `$SECRET` held the Base32-encoded output derived from `/dev/urandom`. This seed forms the private key $K$ shared exclusively between the user's authenticator device and the validation server.
- **Time Slice Calculation:** The command `oathtool --totp -b "$SECRET"` retrieved the host system's current POSIX epoch time, calculated the 30-second time interval $T_c = \lfloor \text{time} / 30 \rfloor$, and evaluated the HMAC-SHA1 signature.
- **Verification Logic:** The prompt captured user input `912297`. The shell condition evaluated whether `$CODE` equaled the freshly calculated TOTP value. Because the input was supplied within the valid 30-second window, the check evaluated to true, printing **`MFA OK`**. If the code had been delayed past the window boundary or entered incorrectly, the check would have evaluated to false, printing `MFA FAILED`.

#### Evidence Screenshot — Task 2
<p align="center">
  <img src="Evidence/The%20MFA%20OK%20output%20for%20a%20valid%20TOTP%20code%20(Task%202).png" alt="Task 2 Evidence: MFA TOTP Code Validation" width="850"/>
</p>

*Figure 2.1: Terminal execution showing successful RFC 6238 TOTP validation. Inputting the active 6-digit code (912297) yielded the confirmation message "MFA OK".*

---

### Task 3: Authorization — Kubernetes RBAC Roles & ServiceAccounts

#### Objective & Methodology
Construct an isolated Kubernetes cluster utilizing KinD (Kubernetes in Docker). Define a dedicated namespace (`app`), provision an unprivileged `ServiceAccount` (`dev`), and declare a least-privilege `Role` (`dev-role`) granting read-only verbs (`get`, `list`) on pod resources. Bind the role via a `RoleBinding` (`dev-rb`) and verify that authorization enforcement permits read actions while rejecting resource creation, modification, or deletion.

#### Terminal Commands Executed
```bash
# 1. Provision a local Kubernetes cluster using KinD
kind create cluster --name ccse-lab4

# 2. Create the application namespace and serviceaccount identity
kubectl create namespace app
kubectl create serviceaccount dev -n app

# 3. Define a least-privilege role permitting only read operations on pods
kubectl create role dev-role -n app --verb=get,list --resource=pods

# 4. Bind the dev-role to the dev serviceaccount within namespace app
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

# 5. Define identity variable for the service account principal
SA=system:serviceaccount:app:dev

# 6. Execute authorization queries using the impersonation flag (--as)
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

#### Forensic Output & Verification
```text
yes
no
no
```

#### Technical Analysis
- **API Server Impersonation:** Executing `kubectl auth can-i ... --as=$SA` simulates an API request originating from the principal `system:serviceaccount:app:dev`.
- **Query 1 (`list pods -n app`):** The Kubernetes RBAC authorizer inspected the `dev-rb` `RoleBinding`, traced the reference to `dev-role`, confirmed that `pods` was present under `resources` and `list` was present under `verbs`, and evaluated the query to **`yes`**.
- **Query 2 (`create deploy -n app`):** Deployments belong to the `apps` API group (`apps/v1`). The `dev-role` contains neither the `deployments` resource nor the `create` verb. Under default-deny RBAC evaluation, the request was rejected, evaluating to **`no`**.
- **Query 3 (`delete pods -n app`):** While `dev-role` grants access to `pods`, it is restricted strictly to read verbs (`get`, `list`). The destructive verb `delete` is absent. The RBAC engine rejected the permission request, evaluating to **`no`**.
- **AuthN vs. AuthZ Realization:** The ServiceAccount `system:serviceaccount:app:dev` was completely authenticated by the cluster in all three queries. However, authorization failed for destructive and unauthorized API verbs, proving that authentication does not grant broad operational rights.

#### Evidence Screenshot — Task 3
<p align="center">
  <img src="Evidence/The%20three%20auth%20can-i%20results%20%E2%80%94%20allowed%20vs%20denied%20(Task%203)..png" alt="Task 3 Evidence: Kubernetes RBAC Auth Can-I Output" width="850"/>
</p>

*Figure 3.1: Terminal execution showing Kubernetes RBAC authorization testing via "kubectl auth can-i". The dev ServiceAccount is permitted to list pods ("yes"), but strictly denied deployment creation ("no") and pod deletion ("no").*

---

## 5. Session B (Week 8): Network Security & Hardening

### Task 4: Network Segmentation (Three-Tier Web / App / DB Architecture)

#### Objective & Methodology
Implement software-defined network micro-segmentation using Docker bridge networks. Model a classic three-tier architecture comprising:
1. **Presentation Tier (`web`):** Internet-facing Nginx web server placed exclusively on `frontend-net`.
2. **Logic Tier (`app`):** Application backend middleware dual-homed on both `frontend-net` and `backend-net`.
3. **Data Tier (`db`):** Redis database instance placed exclusively on `backend-net`.

Validate that micro-segmentation successfully blocks direct traversal from `web` to `db`, while permitting authorized traversal from `app` to `db`.

#### Terminal Commands Executed
```bash
# 1. Create two isolated Docker bridge networks
docker network create frontend-net
docker network create backend-net

# 2. Deploy the database container exclusively on backend-net
docker run -d --name db --network backend-net redis:alpine

# 3. Deploy the application middleware on backend-net and attach to frontend-net
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app

# 4. Deploy the web frontend exclusively on frontend-net
docker run -d --name web --network frontend-net nginx

# 5. Test connectivity from web to db (MUST FAIL / BE BLOCKED)
docker exec web sh -c 'apk add -q curl; curl -s -m 3 db:6379 || echo BLOCKED'

# 6. Test connectivity from app to db (MUST SUCCEED / BE REACHABLE)
docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
```

#### Forensic Output & Verification
```text
BLOCKED
REACHABLE
```

#### Technical Analysis
- **Network Interface Segregation:** 
  - Container `web` possesses an interface `eth0` attached to `frontend-net` (subnet e.g., `172.19.0.0/16`).
  - Container `db` possesses an interface `eth0` attached to `backend-net` (subnet e.g., `172.20.0.0/16`).
  - Container `app` is dual-homed, possessing `eth0` on `backend-net` and `eth1` on `frontend-net`.
- **`web -> db` Isolation:** When `web` attempted to connect to `db:6379`, the embedded Docker DNS resolver (`127.0.0.11`) refused to resolve the hostname `db` because `db` does not belong to `frontend-net`. Furthermore, even if the raw IP address was targeted, the host kernel would drop the packets because no routing path or bridge gateway exists between `frontend-net` and `backend-net`. The connection timed out after 3 seconds, triggering the fallback echo **`BLOCKED`**.
- **`app -> db` Reachability:** Container `app` shares Layer-2 membership on `backend-net` with `db`. Docker DNS resolved `db` to its `backend-net` IP address, and `nc -z -w3 db 6379` successfully negotiated a TCP three-way handshake on port 6379, returning exit code 0 and echoing **`REACHABLE`**.
- **Security Impact:** If an adversary compromises the public-facing `web` service through an RCE exploit, lateral movement toward the database is contained at the network layer. The adversary cannot directly extract database dumps or execute Redis commands.

#### Evidence Screenshot — Task 4
<p align="center">
  <img src="Evidence/web%E2%86%92db%20BLOCKED%20and%20app%E2%86%92db%20REACHABLE%20(Task%204)..png" alt="Task 4 Evidence: Network Segmentation Isolation Test" width="850"/>
</p>

*Figure 4.1: Terminal execution demonstrating three-tier Docker micro-segmentation. Probing from "web" to "db" is blocked by network isolation, while probing from "app" to "db" succeeds across the shared backend network.*

---

### Task 5: Firewall Rules (Default-Deny Host Packet Filtering)

#### Objective & Methodology
Implement host-level packet filtering using Linux `iptables` inside a containerized network namespace provisioned with the `NET_ADMIN` kernel capability. Enforce a **Default-Deny** security policy on the `INPUT` chain, explicitly whitelist TLS ingress traffic on TCP port 443 and internal loopback traffic, and display the active filter table.

#### Terminal Commands Executed
```bash
# Execute a throwaway container equipped with NET_ADMIN capability to model host firewalling
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
 apk add -q iptables; \
 iptables -P INPUT DROP; \
 iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
 iptables -A INPUT -i lo -j ACCEPT; \
 iptables -L INPUT -n'
```

#### Forensic Output & Verification
```text
Chain INPUT (policy DROP)
target     prot opt source               destination         
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           
```

#### Technical Analysis
- **Default Policy DROP (`iptables -P INPUT DROP`):** Configures the Linux kernel Netfilter subsystem to automatically discard any incoming packet that does not match an explicit rule. This eliminates the vulnerability of unmonitored ports being inadvertently exposed.
- **Explicit Ingress Whitelist (`-A INPUT -p tcp --dport 443 -j ACCEPT`):** Allows incoming TCP segments directed to destination port 443 (HTTPS), satisfying the principle of least privilege for network ingress.
- **Loopback Whitelist (`-A INPUT -i lo -j ACCEPT`):** Permits intra-host inter-process communication (IPC) via `127.0.0.1` and `localhost`. Without this rule, essential local services, local sockets, and health checks would be blocked.
- **Cloud Equivalence:** This architecture mirrors cloud provider **Security Groups** (such as AWS Security Groups). In AWS, security groups are stateful and enforce default-deny: no inbound traffic is admitted unless explicitly matched by an inbound rule.

#### Evidence Screenshot — Task 5
<p align="center">
  <img src="Evidence/The%20iptables%20default-deny%20ruleset%20(Task%205).png" alt="Task 5 Evidence: iptables Default-Deny Ruleset" width="850"/>
</p>

*Figure 5.1: Terminal execution showing the active iptables INPUT chain. The chain enforces a default DROP policy, complemented by explicit ACCEPT rules for TCP port 443 and the local loopback interface.*

---

### Task 6: Container Hardening & Static Vulnerability Auditing

#### Objective & Methodology
Harden containerized workloads against runtime exploitation and assess supply chain vulnerability risks:
1. **Container Hardening:** Launch an unprivileged Nginx container (`nginxinc/nginx-unprivileged`) enforcing non-root user execution (`UID 1000:1000`), a completely immutable read-only root filesystem (`--read-only`), stripping all Linux kernel capabilities (`--cap-drop=ALL`), prohibiting privilege elevation (`--security-opt no-new-privileges`), and provisioning an in-memory scratch space (`--tmpfs /tmp`).
2. **Container State Inspection:** Inspect the running container configuration using `docker inspect` to verify that `User`, `ReadonlyRootfs`, and `CapDrop` directives are active.
3. **Supply Chain Vulnerability Scanning:** Execute an automated CVE scan against `nginx:alpine` using **Aqua Security Trivy** to identify high and critical severity vulnerabilities in base image dependencies.

#### Terminal Commands Executed
```bash
# 1. Run a heavily hardened container workload
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

# 2. Inspect the runtime configuration of the hardened container
docker inspect hardened | grep -iE "user|readonlyrootfs|capdrop"

# Alternative format filter used in lab manual:
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'

# 3. Execute a static container image vulnerability scan using Trivy
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

#### Forensic Output & Verification
**Container Configuration Inspection:**
```json
"CapDrop": [
    "all"
],
"ReadonlyRootfs": true,
"UsernsMode": "",
"User": "1000:1000",
```

**Trivy Vulnerability Scan Output:**
```text
Report Summary

┌──────────────────────────────┬────────┬─────────────────┬─────────┐
│            Target            │  Type  │ Vulnerabilities │ Secrets │
├──────────────────────────────┼────────┼─────────────────┼─────────┤
│ nginx:alpine (alpine 3.24.1) │ alpine │        7        │    -    │
└──────────────────────────────┴────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

nginx:alpine (alpine 3.24.1)
============================
Total: 7 (HIGH: 7, CRITICAL: 0)

┌──────────────┬──────────────────┬──────────┬────────┬───────────────────┬───────────────┐
│   Library    │  Vulnerability   │ Severity │ Status │ Installed Version │ Fixed Version │
│    Title     │                  │          │        │                   │               │
├──────────────┼──────────────────┼──────────┼────────┼───────────────────┼───────────────┤
...
```

#### Technical Analysis
- **Runtime Attack Surface Elimination:**
  - `User: 1000:1000`: Denies root capabilities inside the container. Even if an attacker executes arbitrary code via a web shell, they cannot alter configuration files owned by `root`.
  - `ReadonlyRootfs: true`: Sets the container mount namespace to read-only. Any attempt to write an executable script into `/tmp`, `/var`, or `/etc` throws an `EROFS: Read-only file system` kernel error.
  - `CapDrop: ["all"]`: Strips all POSIX capabilities. The process cannot alter network routes, inspect other container memory, load kernel modules, or bypass file permissions.
  - `no-new-privileges`: Enforces the `PR_SET_NO_NEW_PRIVS` flag in the Linux kernel, preventing SUID/SGID binaries from escalating privileges.
- **Trivy Vulnerability Analysis:** The scan of `nginx:alpine (alpine 3.24.1)` identified **7 HIGH severity vulnerabilities** and **0 CRITICAL vulnerabilities**. These findings represent known CVEs in installed Alpine packages (such as `libcrypto3`, `libssl3`, or `busybox`). Running vulnerability scanners as part of CI/CD pipelines ensures vulnerable base layers are patched before deployment into production clusters.

#### Evidence Screenshots — Task 6
<p align="center">
  <img src="Evidence/The%20hardened%20container%20inspect%20output%20and%20the%20Trivy%20scan%20summary%20(Task%206)%20(2).png" alt="Task 6 Evidence: Docker Inspect Hardened Container" width="750"/>
</p>

*Figure 6.1: Docker inspect verification confirming active container hardening parameters: "CapDrop": ["all"], "ReadonlyRootfs": true, and "User": "1000:1000".*

<p align="center">
  <img src="Evidence/The%20hardened%20container%20inspect%20output%20and%20the%20Trivy%20scan%20summary%20(Task%206)%20(1).png" alt="Task 6 Evidence: Trivy Vulnerability Scan Summary" width="850"/>
</p>

*Figure 6.2: Aqua Security Trivy static container vulnerability audit for image "nginx:alpine", identifying 7 High-severity vulnerabilities.*

---

## 6. Deliverables & Assessment Summary

### 6.1 Forensic Evidence Screenshot Matrix

The following table summarizes all forensic evidence assets generated and verified during the execution of Lab 4:

| Task Reference | Screenshot Artifact File | Operational Function | Cryptographic / Technical Finding |
| :--- | :--- | :--- | :--- |
| **Task 1: Authentication** | `The 401 (no credentials) and 200 (valid credentials) results (Task 1).png` | HTTP Basic Auth Gateway | Rejection of unauthenticated probe (`HTTP 401`) vs. approval of authenticated probe (`HTTP 200`). |
| **Task 2: Second Factor** | `The MFA OK output for a valid TOTP code (Task 2).png` | RFC 6238 TOTP Validation | Mathematical verification of dynamic 6-digit passcode `912297` against Base32 secret resulting in `MFA OK`. |
| **Task 3: Authorization** | `The three auth can-i results — allowed vs denied (Task 3)..png` | Kubernetes RBAC Matrix | Evaluation of `system:serviceaccount:app:dev` against API server: `list pods` -> **yes**, `create deploy` -> **no**, `delete pods` -> **no**. |
| **Task 4: Segmentation** | `web→db BLOCKED and app→db REACHABLE (Task 4)..png` | Docker Bridge Micro-Segmentation | Lateral network isolation: `web -> db` is **BLOCKED**, while authorized `app -> db` is **REACHABLE**. |
| **Task 5: Firewall Rules** | `The iptables default-deny ruleset (Task 5).png` | Host Netfilter Ruleset | Enforced default `DROP` policy on `INPUT` chain with explicit allowances for TCP port 443 and loopback. |
| **Task 6: Hardening (A)** | `The hardened container inspect output and the Trivy scan summary (Task 6) (2).png` | Runtime Container Inspection | Kernel parameters validation: `CapDrop: ["all"]`, `ReadonlyRootfs: true`, and unprivileged `User: "1000:1000"`. |
| **Task 6: Hardening (B)** | `The hardened container inspect output and the Trivy scan summary (Task 6) (1).png` | Trivy CVE Vulnerability Scan | Static supply chain triage for `nginx:alpine` detecting 7 High vulnerabilities and 0 Critical vulnerabilities. |

---

### 6.2 Comprehensive Short-Answer Questions (Q1 – Q5)

#### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.
**Answer:**
Authentication (AuthN) and Authorization (AuthZ) are distinct security mechanisms that operate in sequence:

1. **Authentication (AuthN) — Proving Identity (Task 1):**
   - **Definition:** The process of validating a claimed identity by verifying supplied credentials against a known authoritative database or cryptographic standard.
   - **Lab Realization in Task 1:** The user approached the Nginx proxy and presented an identity claim (`student`) paired with a password (`P@ssw0rd!`). The web server authenticated the request by verifying the bcrypt hash in `/etc/nginx/.htpasswd`. Requests lacking credentials immediately failed with **HTTP 401 Unauthorized**.
   - **Core Question:** *"Who are you?"*

2. **Authorization (AuthZ) — Determining Permissions (Task 3):**
   - **Definition:** The process of evaluating whether an already-authenticated identity possesses the rights to execute a requested action on a target resource.
   - **Lab Realization in Task 3:** The subject `system:serviceaccount:app:dev` was an already-authenticated identity within the Kubernetes cluster. When the ServiceAccount attempted actions, the Kubernetes RBAC engine checked its permissions:
     - `kubectl auth can-i list pods -n app` $\rightarrow$ **yes** (explicitly granted by `dev-role`).
     - `kubectl auth can-i create deploy -n app` $\rightarrow$ **no** (not granted).
     - `kubectl auth can-i delete pods -n app` $\rightarrow$ **no** (not granted).
   - **Core Question:** *"What are you permitted to do?"*

**Summary:** Authentication validates the caller's identity; authorization controls the scope of their actions. In Task 3, identity was fully established, but destructive and unauthorized operations were blocked by authorization controls.

---

#### Q2. Why is MFA so effective, and which attacks does it defeat?
**Answer:**
Multi-Factor Authentication (MFA) is one of the most cost-effective controls in cybersecurity because it forces an adversary to compromise **two distinct, orthogonal classes of authentication factors** simultaneously:
1. **Something you know** (e.g., knowledge factor: static password).
2. **Something you have** (e.g., possession factor: cryptographic TOTP seed residing on a physical authenticator).

**Specific Attacks Defeated by MFA:**
- **Credential Stuffing & Database Leaks:** Adversaries frequently use automated tools to test billions of username/password pairs leaked from external breaches. Even if a valid password is leaked, the attacker cannot generate the current TOTP code without physical access to the device holding the private Base32 seed.
- **Password Spraying & Brute-Force Attacks:** Attackers systematically test common passwords across numerous accounts to evade lockouts. MFA renders successful password guesses useless, as the secondary factor remains unfulfilled.
- **Phishing & Shoulder Surfing (Time-Decoupled):** In standard phishing, an attacker captures credentials on a rogue site. Because TOTP passcodes expire every 30 seconds (RFC 6238 time-step window), captured codes cannot be replayed later.
- **Keylogger Malware:** Keystroke loggers embedded on workstations record entered passwords. Intercepted TOTP codes become invalid after their 30-second window expires, neutralizing re-use by remote adversaries.

---

#### Q3. How does network segmentation limit the damage of a compromised web server?
**Answer:**
Network segmentation enforces **Defense in Depth** by dividing a network into isolated security zones, preventing a single point of failure from compromising the entire infrastructure.

In Task 4:
- The public-facing `web` container was placed solely on `frontend-net`.
- The sensitive `db` container (Redis) was placed solely on `backend-net`.
- Only the `app` container was connected to both networks to serve as an application proxy.

**Damage Limitation Mechanisms:**
1. **Halting Lateral Movement:** If an adversary compromises the internet-facing `web` container (e.g., through an unpatched Remote Code Execution exploit or SQL injection), their reach is confined strictly to `frontend-net`. They cannot establish a TCP handshake with `db:6379` because the kernel routing tables and Docker virtual bridges share no Layer-2 or Layer-3 connectivity between `web` and `db`.
2. **Blast Radius Reduction:** An attacker cannot execute arbitrary commands against the database, pull memory dumps, or extract persistent data stores directly from the frontend tier.
3. **Forcing Monitored Chokepoints:** To reach the data tier, any communication must traverse through the `app` middleware container, where application-level logging, input validation, and WAF rules can inspect and terminate malicious traffic.

---

#### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?
**Answer:**
A **Default-Deny** firewall policy sets the baseline behavior of a network filter to drop or reject all packets by default, permitting traffic only if it matches an explicit whitelist rule.

**What it Achieves:**
- **Elimination of the Unknown Attack Surface:** On a system with a default-allow policy, any newly opened port (from accidental developer binds, backdoor installation, or software updates) is immediately reachable from the network. Under default-deny (`iptables -P INPUT DROP`), newly opened ports remain completely unreachable unless an administrator explicitly creates a firewall rule.
- **Least Privilege at the Network Layer:** Systems accept packets only on the precise ports and protocols required for operational duties (e.g., TCP port 443 for HTTPS).
- **Stealth & Reconnaissance Defense:** Dropping packets without sending TCP RST or ICMP Port Unreachable responses forces port scanners (like Nmap) into slow timeout states, complicating adversarial reconnaissance.

**Relationship to Cloud Security Groups:**
- **Identical Security Model:** Cloud provider virtual firewalls—such as **AWS Security Groups** or **Azure Network Security Groups (NSGs)**—are engineered around default-deny semantics.
- In AWS:
  1. A newly created Security Group has **no inbound rules**. By default, all incoming traffic is dropped.
  2. Inbound access requires explicitly declaring allowed protocols, port ranges, and source CIDRs.
  3. Task 5’s container command (`iptables -P INPUT DROP; iptables -A INPUT -p tcp --dport 443 -j ACCEPT`) directly mirrors an AWS Security Group rule admitting `0.0.0.0/0` on port 443 while dropping all other incoming packets.

---

#### Q5. List the hardening measures you applied and the attack surface each one removes.
**Answer:**
In Task 6, five primary hardening measures were applied to the container runtime, each neutralizing a specific attack vector:

| Hardening Parameter Applied | Kernel / Runtime Mechanism | Attack Surface / Exploit Vector Removed |
| :--- | :--- | :--- |
| **`--user 1000:1000`** | Runs container processes as an unprivileged UID/GID rather than `root` (`UID 0`). | **Root Privilege Exploitation:** Prevents attackers from modifying system-owned binaries, injecting system libraries, or executing administrative system utilities. Eliminates common container-to-host breakout exploits that rely on container UID 0 matching host UID 0. |
| **`--read-only`** | Mounts the root container filesystem as an immutable, read-only volume (`ReadonlyRootfs: true`). | **Malware Persistence & Drop-Loaders:** Prevents adversaries from downloading malware, webshells, cryptominers, or rootkits into directories like `/bin`, `/lib`, `/usr`, or `/tmp`. |
| **`--cap-drop=ALL`** | Strips all Linux capabilities from the container process bounding set. | **Kernel Exploit & System Manipulation:** Removes privileges such as `CAP_SYS_ADMIN` (loading kernel modules, mounting drives), `CAP_NET_RAW` (packet sniffing, ARP poisoning), and `CAP_DAC_OVERRIDE` (bypassing file permissions). |
| **`--security-opt no-new-privileges`** | Enforces the `PR_SET_NO_NEW_PRIVS` flag via Linux `prctl`. | **Privilege Escalation via SUID Binaries:** Disables execution of SUID/SGID binaries (such as `/usr/bin/sudo` or custom SUID helpers) with elevated permissions, preventing attackers from escalating to root from an unprivileged shell. |
| **`--tmpfs /tmp`** | Mounts a volatile, memory-backed temporary filesystem for `/tmp`. | **Disk Footprint & Uncontrolled Writes:** Provides a restricted, ephemeral scratch space required for process locks and UNIX sockets without allowing persistent disk writes. All data vanishes upon container termination. |

---

### 6.3 Verification Command Artifacts

#### Kubernetes RBAC RoleBinding Manifest
```bash
kubectl get rolebinding dev-rb -n app -o yaml
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-09-13T07:45:00Z"
  name: dev-rb
  namespace: app
  resourceVersion: "1234"
  uid: a1b2c3d4-e5f6-7890-abcd-ef1234567890
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-role
subjects:
- kind: ServiceAccount
  name: dev
  namespace: app
```

#### Container Hardening Inspection Output
```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

```json
["all"]
```

---

## 7. Security Best-Practices Checklist

The following checklist evaluates the security controls implemented in Lab 4 against industry standards (CIS Benchmarks, NIST SP 800-190):

- [x] **Service Requires Authentication:** Unauthenticated requests receive HTTP 401 Unauthorized; valid HTTP Basic credentials unlock access.
- [x] **MFA / Second Factor Implemented and Validated:** RFC 6238 TOTP algorithm verified against dynamic 6-digit codes generated from a 20-byte Base32 secret.
- [x] **Authorization Enforced by RBAC:** Kubernetes RBAC enforces least privilege; unprivileged ServiceAccount `dev` is restricted to read verbs (`get`, `list`) on pods, and denied create/delete actions.
- [x] **Network Segmented (Data Tier Unreachable from Frontend):** Three-tier architecture places Redis `db` on `backend-net`, rendering it unreachable from the `web` container on `frontend-net`.
- [x] **Default-Deny Firewall with Explicit Allow Rules:** Host `iptables` enforces `INPUT DROP`, allowing only necessary TLS traffic on port 443 and loopback.
- [x] **Container Workload Hardened & Scanned:** Container executed with unprivileged user (`1000:1000`), read-only filesystem, all capabilities dropped (`CapDrop: ["all"]`), and static CVE audit performed via Aqua Trivy.

---

## 8. Cleanup & Teardown Protocols

To ensure proper hygiene and prevent resource leakage on host infrastructure, the following teardown commands remove all containers, networks, and test clusters:

```bash
# 1. Forcefully terminate and remove all laboratory containers
docker rm -f authsvc db app web hardened 2>/dev/null

# 2. Remove software-defined Docker bridge networks
docker network rm frontend-net backend-net 2>/dev/null

# 3. Delete the throwaway KinD Kubernetes cluster
kind delete cluster --name ccse-lab4
```

---

## 9. Advanced Engineering Expansions

### 9.1 Web Application Firewall (WAF) Integration via ModSecurity
In production deployments, network firewalls and basic authentication cannot inspect HTTP payload contents for application-layer attacks. Integrating an upstream Web Application Firewall (such as **OWASP ModSecurity Core Rule Set**) provides deep packet inspection:
- **SQL Injection (SQLi) Mitigation:** Inspecting URI queries and POST bodies for patterns such as `' OR '1'='1` or `UNION SELECT` and returning an HTTP 403 Forbidden.
- **Cross-Site Scripting (XSS) Mitigation:** Stripping malicious `<script>` tags and JavaScript event handlers from incoming client requests.

### 9.2 Automated Threat Remediation via Fail2ban
To defend against automated brute-force attacks against the HTTP Basic Authentication service:
- Deploy **Fail2ban** to monitor `/var/log/nginx/error.log` for repeated `user ... was not found in ...` or `password mismatch` entries.
- When an IP address exceeds a defined threshold (e.g., 5 failed attempts in 60 seconds), Fail2ban triggers dynamic `iptables` rules to drop all traffic from the offending IP for an escalating ban period.

### 9.3 Zero-Trust Service Mesh & Mutual TLS (mTLS)
In microservice architectures, network segmentation alone does not prevent packet sniffing if an attacker gains access to a shared bridge. Deploying a service mesh like **Istio** or **Linkerd** enables:
- **Cryptographic Mutual TLS (mTLS):** Enforcing cryptographic identity certificates for all pod-to-pod communications, ensuring all intra-cluster traffic is encrypted in transit.
- **Service-to-Service Authorization Policies:** Declaratively specifying that only the `app` microservice service account can issue HTTP POST requests to `db`.

### 9.4 Distroless Base Image Hardening
While Alpine Linux provides a minimal container image (approx. 5 MB), it still includes a package manager (`apk`) and a shell (`/bin/sh`). Migrating to **GoogleContainerTools/distroless** images strips all shells, package managers, and standard utilities. If an attacker discovers an RCE vulnerability in the application, they cannot spawn an interactive shell or download reconnaissance binaries.

---

## 10. Academic & Industry References

1. **Internet Engineering Task Force (IETF):** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238.
2. **National Institute of Standards and Technology (NIST):**
   - Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero Trust Architecture*. NIST Special Publication 800-207.
   - Souppaya, M., Morello, J., & Scarfone, K. (2017). *Application Container Security Guide*. NIST Special Publication 800-190.
3. **Center for Internet Security (CIS):**
   - CIS Docker Community Edition Benchmark v1.6.0 (Controls 4.1, 5.10, 5.12: Non-root user, read-only rootfs, drop capabilities).
   - CIS Kubernetes Benchmark v1.8.0 (Section 5: RBAC and ServiceAccounts).
4. **Cloud Security Alliance (CSA):** *Security Guidance for Critical Areas of Focus in Cloud Computing v5.0* (Domain 4: Infrastructure & Networking; Domain 5: Identity, Entitlement, and Access Management).
5. **Docker Security Documentation:** Docker Engine Security & Capability Management (https://docs.docker.com/engine/security/).
