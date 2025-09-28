Purpose
==========================================================

This project emulates an ADCS enrollment server (not a client). It mimics the behavior of Microsoft ADCS Web Enrollment endpoints (CEP/CES) to handle certificate requests.

- **Certificate Enrollment Policy (CEP)** — exposes a policy endpoint 
  to provide enrollment templates and CA information to clients.
- **Certificate Enrollment Services (CES)** — emulates the service that 
  accepts CSRs and returns signed certificates.

The goal is to emulate an ADCS web enrollment server that:

- Serves CEP policy (templates, CAs, etc.) to requesting clients.
- Receives and validates PKCS#10 CSRs.
- Processes submissions via CES and returns signed responses.
  
🚨 Limitations/Status
----------------------------------------------------------

- Minimal testing
- Not audited for security
- Only tested in isolated **lab environments**
- No guarantees of correctness or compatibility
- Much of the code was created using AI.


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



ADCS Python Installation
==========================================

Requirements
-------------------

- Linux server (Debian/Ubuntu) (not ad server)
- Root access
- A functional Active Directory domain

Install dependencies
---------------------------------------------------------

```
apt-get update
apt-get install -y \
       samba \
       msktutil \
       nginx \
       python3-flask \
       python3-asn1crypto \
       python3-kerberos \
       krb5-user \
       git \
       python3-defusedxml \
       python3-pyasn1 \
       python3-waitress
```

Retrieve the project
---------------------------------------------------------

```
cd /opt
git clone https://github.com/sfonteneau/adcs_python.git
cd adcs_python
```   

Create a local CA (for testing)
---------------------------------------------------------
 
```
bash create_ca.sh
```

Initial configuration
---------------------------------------------------------

- Copy the configuration template:

```
cp -f /opt/adcs_python/adcs.yaml.template /opt/adcs_python/adcs.yaml
```

- Edit ``adcs.yaml`` if needed.

- Create the request directory:

```
mkdir /opt/adcs_python/list_request_id
```

Configure Nginx certificates
---------------------------------------------------------

```
cp -f /opt/adcs_python/pki/private/testadcs.mydomain.lan.key.pem /etc/nginx/key.pem
cp -f /opt/adcs_python/pki/certs/testadcs.mydomain.lan.fullchain.pem /etc/nginx/crt.pem
```

Configure Nginx
---------------------------------------------------------

- Replace the default configuration:

```
cp -f /opt/adcs_python/nginx-conf.conf.template /etc/nginx/sites-enabled/default
```

- Generate Diffie-Hellman parameters:

```
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

Join the Active Directory domain
---------------------------------------------------------


- Edit ``/etc/krb5.conf`` for your domain.
- Test with:

```
kinit <user>@MYDOMAIN.LAN
net ads join
```

- In ``/etc/samba/smb.conf`` add:

```
kerberos method = secrets and keytab
```

Manage SPN and Keytab
---------------------------------------------------------

- In Active Directory, register the HTTP SPN for the machine account:

```
HTTP/testadcs.mydomain.lan
```

- Generate the keytab:

```
net ads keytab create
```

- Add the machine FQDN and IP address to ``/etc/hosts``.

Start the ADCS Python server
---------------------------------------------------------

```
cd /opt/adcs_python && python3 app.py
```

- (Optional) Create a **systemd** service to start ADCS automatically.

Test on a Windows client
---------------------------------------------------------

- Install the root CA generated: ``/opt/adcs_python/pki/certs/ca.crt.pem``  
- Install the intermediate CA generated: ``/opt/adcs_python/pki/certs/ica.crt.pem``  

- In the Windows **MMC Certificates** console → **Personal** → **Certificates** → *Request a certificate*  
  → Provide the service URL, for example:

```
https://testadcs.mydomain.lan/CEP
```

  *(The URL can be configured via GPO.)*

Desired enhancements for the project.
==========================================


- certsrv emulation : Emulate Microsoft ADCS `certsrv` web enrollment.

- EST/SCEP : Support device enrollment via EST and SCEP for network gear, MDM, and IoT bootstrapping.

- ACME : Provide ACME endpoints for automated issuance/renewal (e.g., HTTP-01/DNS-01 challenges).

- Interface management : Offer a simple management surface (CLI/API) for policies, status, and audit tasks.

