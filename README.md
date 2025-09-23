
🚨 WARNING — EXPERIMENTAL ONLY
==========================================================

This project is an **experimental proof of concept**.  
**Do not use in production** — it is unstable, unaudited, and not security-hardened.  
You risk **bugs, data loss, and security issues**.


Purpose
----------------------------------------------------------

This project emulates an ADCS enrollment server (not a client). It mimics the behavior of Microsoft ADCS Web Enrollment endpoints (CEP/CES) to handle certificate requests.

- **Certificate Enrollment Policy (CEP)** — exposes a policy endpoint 
  to provide enrollment templates and CA information to clients.
- **Certificate Enrollment Services (CES)** — emulates the service that 
  accepts CSRs and returns signed certificates.

The goal is to emulate an ADCS web enrollment server that:

- Serves CEP policy (templates, CAs, etc.) to requesting clients.
- Receives and validates PKCS#10 CSRs.
- Processes submissions via CES and returns signed responses.
  

Status
----------------------------------------------------------

- 🚧 **POC / unstable**
- Minimal testing
- Many missing features (TODOs)
- Not designed or safe for real-world deployment


Limitations
----------------------------------------------------------

- Not audited for security
- Protocol implementation incomplete
- Only tested in isolated **lab environments**
- No guarantees of correctness or compatibility

Intended Use
----------------------------------------------------------

✅ For lab experiments and prototype testing  
❌ **Not for production**  


## 🔧 Certificate Templates via Callback

In this project, certificate **templates** (CEP/CES) are not hardcoded in the server.  
Instead, they are defined through **Python callbacks**.  

Each template is represented by an external module (e.g. `callbacks/user_template.py`) exposing two required functions:

- **`define_template(app_conf, kerberos_user)`**  
  → Dynamically describes the template properties (OID, EKU, KeyUsage, validity period, etc.) depending on the user or context.

- **`emit_certificate(...)`**  
  → Takes the CSR and metadata as input, applies the necessary extensions, and issues the certificate signed by the CA.

### Why callbacks?
- Provides **maximum flexibility**: template logic can depend on Active Directory attributes, group membership, external policies, or any business rule.  
- Avoids locking the CA server into static, predefined templates.

### ⚠️ Security responsibility
This design shifts most of the **security checks** to the callback author.  
In practice:
- **Eligibility checks** (who is allowed to get what kind of certificate) must be implemented **inside the callback** (e.g. enforce AD group membership, adjust validity periods, or restrict EKUs).  
- If the callback does not enforce checks, **any authenticated user could obtain any certificate** that the module returns.  
- The Python ADCS server does not impose extra restrictions: it simply executes the callback and signs the result.

👉 **In short: the security and enforcement of issuance rules are entirely the responsibility of the callback code.**


