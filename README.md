
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


TODO / Roadmap
----------------------------------------------------------

- Add security hardening and authentication (Kerberos, NTLM, etc.)
- Improve PKCS#10 CSR handling
- Expand test coverage (unit + integration)
- Provide detailed technical documentation
- Support more advanced enrollment scenarios
