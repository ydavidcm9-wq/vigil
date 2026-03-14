'use strict';

/**
 * Cross-Framework Compliance Matrix
 *
 * Maps controls across five major compliance frameworks:
 *   - PCI DSS 4.0
 *   - HIPAA Security Rule (45 CFR Part 164)
 *   - SOC 2 Trust Services Criteria (2017)
 *   - ISO 27001:2022 (Annex A)
 *   - CIS Controls v8
 *
 * Each entry provides the exact requirement/control references so compliance
 * officers can trace a single control area across all five frameworks.
 */

const COMPLIANCE_MATRIX = [

  // ──────────────────────────────────────────────────────────
  // 1. Access Control
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-ACCESS',
    domain: 'compliance',
    title: 'Access Control Requirements',
    content:
      'Access control is required across all major frameworks. ' +
      'PCI DSS 4.0: Req 7 (Restrict access by business need-to-know), Req 8 (Identify users and authenticate access). ' +
      'HIPAA: 164.312(a)(1) Access Control — unique user ID, emergency access procedure, automatic logoff, encryption/decryption. ' +
      'SOC 2: CC6.1 (Logical and physical access controls implemented), CC6.2 (Prior to issuing system credentials, registration is authorized), CC6.3 (Access granted based on authorization). ' +
      'ISO 27001:2022: A.5.15 (Access control policy), A.5.18 (Access rights provisioning), A.8.2 (Privileged access rights), A.8.3 (Information access restriction). ' +
      'CIS v8: Control 5 (Account Management), Control 6 (Access Control Management).',
    tags: ['access-control', 'authentication', 'authorization', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://www.hhs.gov/hipaa/',
      'https://www.aicpa.org/soc2',
      'https://www.iso.org/standard/27001',
      'https://www.cisecurity.org/controls/v8'
    ],
    cweIds: ['CWE-284', 'CWE-287'],
    mitreIds: ['T1078', 'T1110'],
    relatedIds: ['COMP-AUTH', 'COMP-AUDIT'],
    detection: 'Access control audit, privilege review, authentication testing, account enumeration',
    mitigation: 'Implement RBAC/ABAC, enforce MFA, conduct regular access reviews, apply principle of least privilege, disable dormant accounts'
  },

  // ──────────────────────────────────────────────────────────
  // 2. Authentication & Multi-Factor Authentication
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-AUTH',
    domain: 'compliance',
    title: 'Authentication & Multi-Factor Authentication',
    content:
      'Strong authentication and MFA are mandated or strongly recommended across all frameworks. ' +
      'PCI DSS 4.0: Req 8.3 (Establish and manage authentication factors), Req 8.4 (MFA for all access into the CDE), Req 8.5 (MFA systems are configured properly). ' +
      'HIPAA: 164.312(d) Person or Entity Authentication — verify identity of persons seeking access to ePHI. ' +
      'SOC 2: CC6.1 (Logical access security, including authentication mechanisms), CC6.6 (System boundaries protected with authentication points). ' +
      'ISO 27001:2022: A.8.5 (Secure authentication), A.5.17 (Authentication information management). ' +
      'CIS v8: Control 6.3 (Require MFA for externally-exposed applications), Control 6.4 (Require MFA for remote network access), Control 6.5 (Require MFA for administrative access).',
    tags: ['authentication', 'mfa', 'identity', 'cross-framework'],
    severity: 'critical',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://www.hhs.gov/hipaa/',
      'https://csrc.nist.gov/publications/detail/sp/800-63b/final'
    ],
    cweIds: ['CWE-287', 'CWE-306', 'CWE-308'],
    mitreIds: ['T1078', 'T1110', 'T1556'],
    relatedIds: ['COMP-ACCESS', 'COMP-KEYMGMT'],
    detection: 'Authentication bypass testing, MFA enumeration, credential stuffing simulation, password policy audit',
    mitigation: 'Enforce MFA on all privileged and remote access, use phishing-resistant authenticators (FIDO2/WebAuthn), enforce strong password policies, implement account lockout'
  },

  // ──────────────────────────────────────────────────────────
  // 3. Encryption (At Rest + In Transit)
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-ENCRYPT',
    domain: 'compliance',
    title: 'Encryption — At Rest and In Transit',
    content:
      'Encryption of sensitive data both at rest and in transit is a universal requirement. ' +
      'PCI DSS 4.0: Req 3.5 (PAN is secured wherever stored — encryption, truncation, hashing), Req 4.2 (PAN is protected with strong cryptography during transmission over open/public networks). ' +
      'HIPAA: 164.312(a)(2)(iv) Encryption and Decryption (addressable — at rest), 164.312(e)(1) Transmission Security — integrity controls and encryption of ePHI in transit, 164.312(e)(2)(ii) Encryption (addressable — in transit). ' +
      'SOC 2: CC6.1 (Data protection in transit and at rest), CC6.7 (Restricting transmission/movement/removal of data). ' +
      'ISO 27001:2022: A.8.24 (Use of cryptography), A.5.14 (Information transfer — secure channels). ' +
      'CIS v8: Control 3.6 (Encrypt data on end-user devices), Control 3.7 (Establish and maintain a data classification scheme), Control 3.9 (Encrypt data on removable media), Control 3.10 (Encrypt sensitive data in transit), Control 3.11 (Encrypt sensitive data at rest).',
    tags: ['encryption', 'cryptography', 'data-protection', 'tls', 'cross-framework'],
    severity: 'critical',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-311', 'CWE-319', 'CWE-327'],
    mitreIds: ['T1040', 'T1557', 'T1565'],
    relatedIds: ['COMP-KEYMGMT', 'COMP-DATACLASS'],
    detection: 'TLS configuration scanning, cipher suite analysis, storage encryption verification, certificate validation',
    mitigation: 'Use TLS 1.2+ for all transmissions, AES-256 for data at rest, enforce certificate validation, deprecate weak cipher suites, use HSMs for key storage'
  },

  // ──────────────────────────────────────────────────────────
  // 4. Audit Logging & Monitoring
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-AUDIT',
    domain: 'compliance',
    title: 'Audit Logging & Monitoring',
    content:
      'Comprehensive audit logging and real-time monitoring are required for detecting and investigating security events. ' +
      'PCI DSS 4.0: Req 10.1 (Processes and mechanisms for logging and monitoring are defined and documented), Req 10.2 (Audit logs capture activities), Req 10.3 (Audit logs are protected from destruction and unauthorized modifications), Req 10.4 (Audit logs are reviewed), Req 10.5 (Audit log history is retained — 12 months, 3 months immediately available). ' +
      'HIPAA: 164.312(b) Audit Controls — mechanisms to record and examine access/activity in systems with ePHI, 164.308(a)(1)(ii)(D) Information System Activity Review. ' +
      'SOC 2: CC7.1 (Detection of changes to configuration/infrastructure), CC7.2 (Monitoring for anomalies and security events), CC7.3 (Evaluating security events). ' +
      'ISO 27001:2022: A.8.15 (Logging), A.8.16 (Monitoring activities), A.8.17 (Clock synchronization). ' +
      'CIS v8: Control 8 (Audit Log Management — 8.1 establish process, 8.2 collect audit logs, 8.5 collect detailed audit logs, 8.9 centralize audit logs, 8.11 conduct audit log reviews, 8.12 collect service provider logs).',
    tags: ['audit', 'logging', 'monitoring', 'siem', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://csrc.nist.gov/publications/detail/sp/800-92/final'
    ],
    cweIds: ['CWE-778', 'CWE-223', 'CWE-779'],
    mitreIds: ['T1070', 'T1562.002'],
    relatedIds: ['COMP-INCIDENT', 'COMP-ACCESS'],
    detection: 'Log completeness review, log integrity verification, SIEM rule coverage assessment, time synchronization check',
    mitigation: 'Centralize logs in SIEM, protect log integrity with WORM storage, enforce NTP synchronization, retain 12+ months, implement real-time alerting for critical events'
  },

  // ──────────────────────────────────────────────────────────
  // 5. Incident Response
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-INCIDENT',
    domain: 'compliance',
    title: 'Incident Response',
    content:
      'All frameworks require a documented incident response capability with defined roles, communication plans, and lessons-learned processes. ' +
      'PCI DSS 4.0: Req 12.10 (Suspected and confirmed security incidents that could impact the CDE are responded to immediately — 12.10.1 IR plan, 12.10.2 plan reviewed/tested annually, 12.10.4 appropriate training, 12.10.5 alerts from security monitoring, 12.10.6 evolve IR plan based on lessons learned). ' +
      'HIPAA: 164.308(a)(6) Security Incident Procedures — 164.308(a)(6)(i) Response and Reporting (required implementation specification). ' +
      'SOC 2: CC7.3 (Procedures exist to evaluate security events), CC7.4 (Procedures exist to respond to identified security incidents), CC7.5 (Procedures exist to identify and remediate identified vulnerabilities). ' +
      'ISO 27001:2022: A.5.24 (Information security incident management planning and preparation), A.5.25 (Assessment and decision on information security events), A.5.26 (Response to information security incidents), A.5.27 (Learning from information security incidents), A.5.28 (Collection of evidence). ' +
      'CIS v8: Control 17 (Incident Response Management — 17.1 designate personnel, 17.2 establish process for reporting, 17.3 establish and maintain an IR process, 17.4 establish communication procedures, 17.6 define mechanisms for communicating during IR, 17.7 conduct routine IR exercises, 17.8 conduct post-incident reviews, 17.9 establish security incident thresholds).',
    tags: ['incident-response', 'breach-notification', 'forensics', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: [],
    mitreIds: ['T1070', 'T1485'],
    relatedIds: ['COMP-AUDIT', 'COMP-RISK'],
    detection: 'IR plan review, tabletop exercise results, incident ticket analysis, mean-time-to-detect/respond metrics',
    mitigation: 'Maintain documented IR plan, conduct annual tabletop exercises, integrate with SIEM alerts, define escalation paths and breach notification timelines, preserve forensic evidence'
  },

  // ──────────────────────────────────────────────────────────
  // 6. Vulnerability Management / Patching
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-VULN',
    domain: 'compliance',
    title: 'Vulnerability Management & Patching',
    content:
      'Regular vulnerability scanning and timely patching are required across all frameworks. ' +
      'PCI DSS 4.0: Req 6.3 (Security vulnerabilities are identified and addressed — 6.3.1 identify vulnerabilities using industry sources, 6.3.3 patch critical/high vulns within defined timeframe), Req 11.3 (External and internal vulnerabilities regularly tested — 11.3.1 internal scans quarterly, 11.3.2 external ASV scans quarterly). ' +
      'HIPAA: 164.308(a)(5)(ii)(B) Protection from Malicious Software (addressable — patch management implied), 164.308(a)(1)(ii)(A) Risk Analysis (must include vulnerability identification). ' +
      'SOC 2: CC7.1 (Configuration and vulnerability management), CC7.5 (Procedures to identify, remediate, and track vulnerabilities). ' +
      'ISO 27001:2022: A.8.8 (Management of technical vulnerabilities), A.8.19 (Installation of software on operational systems). ' +
      'CIS v8: Control 7 (Continuous Vulnerability Management — 7.1 establish process, 7.2 establish remediation process, 7.3 perform automated operating system patch management, 7.4 perform automated application patch management, 7.5 perform automated vulnerability scans of internal assets, 7.6 perform automated vulnerability scans of externally-exposed assets, 7.7 remediate detected vulnerabilities).',
    tags: ['vulnerability-management', 'patching', 'scanning', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.first.org/cvss/',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-1104', 'CWE-1035'],
    mitreIds: ['T1190', 'T1210'],
    relatedIds: ['COMP-PENTEST', 'COMP-CONFIGMGMT'],
    detection: 'Vulnerability scanning (Nessus, Qualys, Rapid7), ASV scan results, patch compliance reporting',
    mitigation: 'Scan quarterly at minimum (monthly preferred), patch critical vulns within 30 days, automate patch deployment, maintain vulnerability tracking database, prioritize by CVSS and exploitability'
  },

  // ──────────────────────────────────────────────────────────
  // 7. Network Security / Segmentation
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-NETWORK',
    domain: 'compliance',
    title: 'Network Security & Segmentation',
    content:
      'Network security controls and segmentation are required to protect sensitive environments and data flows. ' +
      'PCI DSS 4.0: Req 1 (Install and maintain network security controls — 1.2 network security controls configured and maintained, 1.3 network access to/from CDE restricted, 1.4 network connections between trusted/untrusted networks controlled), Req 11.4 (External and internal penetration testing of network segmentation controls). ' +
      'HIPAA: 164.312(e)(1) Transmission Security — integrity controls and encryption, 164.310(b) Workstation Use (physical network controls implied). ' +
      'SOC 2: CC6.1 (Network access restrictions), CC6.6 (System boundary protections — firewalls, IDS/IPS, DMZ), CC6.7 (Restriction of data transmission). ' +
      'ISO 27001:2022: A.8.20 (Networks security), A.8.21 (Security of network services), A.8.22 (Segregation of networks), A.8.23 (Web filtering). ' +
      'CIS v8: Control 9 (Email and Web Browser Protections — network-layer filtering), Control 12 (Network Infrastructure Management — 12.1 ensure network infrastructure is up to date, 12.2 establish and maintain a secure network architecture, 12.3 securely manage network infrastructure, 12.4 establish and maintain architecture diagram, 12.7 ensure remote devices use a VPN, 12.8 establish and maintain dedicated computing resources for admin work).',
    tags: ['network-security', 'segmentation', 'firewall', 'ids-ips', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final'
    ],
    cweIds: ['CWE-284', 'CWE-923'],
    mitreIds: ['T1046', 'T1040', 'T1571'],
    relatedIds: ['COMP-ENCRYPT', 'COMP-WIRELESS'],
    detection: 'Firewall rule review, network segmentation testing, IDS/IPS alert analysis, network topology validation',
    mitigation: 'Implement micro-segmentation, deploy IDS/IPS at trust boundaries, restrict traffic to required ports/protocols, document network architecture, review firewall rules semi-annually'
  },

  // ──────────────────────────────────────────────────────────
  // 8. Data Classification & Protection
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-DATACLASS',
    domain: 'compliance',
    title: 'Data Classification & Protection',
    content:
      'Data must be classified by sensitivity and protected according to its classification level. ' +
      'PCI DSS 4.0: Req 3 (Protect stored account data — 3.1 processes to protect stored account data defined, 3.2 storage of account data minimized, 3.3 SAD not stored after authorization, 3.4 access to displays of PAN restricted, 3.5 PAN secured wherever stored), Req 12.1 (Information security policy addresses data classification). ' +
      'HIPAA: 164.308(a)(1)(ii)(A) Risk Analysis (identify where ePHI resides), 164.530(c) Administrative Requirements — safeguards for PHI, 164.514 De-identification of PHI. ' +
      'SOC 2: CC6.1 (Classification of data and systems), CC6.5 (Data is disposed of securely), CC6.7 (Restriction of data transmission based on classification). ' +
      'ISO 27001:2022: A.5.12 (Classification of information), A.5.13 (Labelling of information), A.5.14 (Information transfer). ' +
      'CIS v8: Control 3 (Data Protection — 3.1 establish and maintain a data management process, 3.2 establish and maintain a data inventory, 3.3 configure data access control lists, 3.4 enforce data retention, 3.5 securely dispose of data, 3.7 establish and maintain a data classification scheme, 3.12 segment data processing and storage based on sensitivity).',
    tags: ['data-classification', 'data-protection', 'dlp', 'privacy', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-200', 'CWE-312', 'CWE-359'],
    mitreIds: ['T1005', 'T1039', 'T1530'],
    relatedIds: ['COMP-ENCRYPT', 'COMP-RETENTION'],
    detection: 'Data discovery scanning, DLP policy audit, data flow mapping, classification label review',
    mitigation: 'Implement data classification scheme, deploy DLP tools, minimize data collection and retention, label all assets by classification, restrict access by classification level'
  },

  // ──────────────────────────────────────────────────────────
  // 9. Change Management
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-CHANGEMGMT',
    domain: 'compliance',
    title: 'Change Management',
    content:
      'Formal change management processes are required to prevent unauthorized modifications to systems and applications. ' +
      'PCI DSS 4.0: Req 6.5 (Changes to all system components in production are managed — 6.5.1 change control procedures, 6.5.2 significant changes documented and approved, 6.5.3 pre-production environments separated from production, 6.5.4 roles and functions separated in dev/test/prod, 6.5.5 live PANs not used in test, 6.5.6 test data and accounts removed). ' +
      'HIPAA: 164.308(a)(8) Evaluation — technical and nontechnical evaluation in response to environmental or operational changes. ' +
      'SOC 2: CC8.1 (Authorization, design, development, configuration, documentation, testing, approval, and implementation of changes to infrastructure, data, software, and procedures). ' +
      'ISO 27001:2022: A.8.32 (Change management), A.5.4 (Management responsibilities — change oversight). ' +
      'CIS v8: Control 2.4 (Use automated software inventory tools — change tracking), Control 4 (Secure Configuration — changes tracked via 4.1), Control 16.12 (Implement code-level security checks in the SDLC).',
    tags: ['change-management', 'change-control', 'sdlc', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://www.itil-docs.com/change-management/',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-439'],
    mitreIds: ['T1195.002'],
    relatedIds: ['COMP-APPSEC', 'COMP-CONFIGMGMT'],
    detection: 'Change ticket audit, unauthorized change detection, separation-of-duties review, rollback testing',
    mitigation: 'Implement formal CAB process, require peer review and approval, test in pre-production, maintain rollback procedures, separate dev/test/prod environments, track all changes in ticketing system'
  },

  // ──────────────────────────────────────────────────────────
  // 10. Backup & Recovery / Business Continuity
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-BACKUP',
    domain: 'compliance',
    title: 'Backup & Recovery / Business Continuity',
    content:
      'Backup, disaster recovery, and business continuity planning are essential for data availability and resilience. ' +
      'PCI DSS 4.0: Req 9.4 (Media with cardholder data is securely stored, accessed, distributed, and destroyed), Req 12.10.1 (IR plan includes business recovery and continuity). ' +
      'HIPAA: 164.308(a)(7) Contingency Plan — 164.308(a)(7)(ii)(A) Data Backup Plan (required), 164.308(a)(7)(ii)(B) Disaster Recovery Plan (required), 164.308(a)(7)(ii)(C) Emergency Mode Operation Plan (required), 164.308(a)(7)(ii)(D) Testing and Revision Procedures (addressable), 164.308(a)(7)(ii)(E) Applications and Data Criticality Analysis (addressable). ' +
      'SOC 2: A1.1 (Recovery objectives defined), A1.2 (System recovery procedures tested), A1.3 (Backup procedures implemented). ' +
      'ISO 27001:2022: A.8.13 (Information backup), A.8.14 (Redundancy of information processing facilities), A.5.29 (ICT readiness for business continuity), A.5.30 (ICT readiness for business continuity — plans). ' +
      'CIS v8: Control 11 (Data Recovery — 11.1 establish and maintain a data recovery process, 11.2 perform automated backups, 11.3 protect recovery data, 11.4 establish and maintain an isolated instance of recovery data, 11.5 test data recovery).',
    tags: ['backup', 'disaster-recovery', 'business-continuity', 'bcp', 'drp', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final',
      'https://www.hhs.gov/hipaa/'
    ],
    cweIds: [],
    mitreIds: ['T1485', 'T1490'],
    relatedIds: ['COMP-INCIDENT', 'COMP-DATACLASS'],
    detection: 'Backup success/failure reports, recovery testing results, RTO/RPO validation, BCP plan review',
    mitigation: 'Automate daily backups, test restoration quarterly, maintain offsite/immutable copies, define RTO/RPO per data classification, conduct annual BCP/DR exercises'
  },

  // ──────────────────────────────────────────────────────────
  // 11. Security Awareness Training
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-TRAINING',
    domain: 'compliance',
    title: 'Security Awareness Training',
    content:
      'Security awareness and training programs are required to ensure all personnel understand their security responsibilities. ' +
      'PCI DSS 4.0: Req 12.6 (Security awareness education — 12.6.1 formal program in place, 12.6.2 reviewed at least annually, 12.6.3 personnel receive training upon hire and annually, 12.6.3.1 training includes awareness of threats like phishing and social engineering, 12.6.3.2 personnel acknowledge security policy annually). ' +
      'HIPAA: 164.308(a)(5) Security Awareness and Training — 164.308(a)(5)(i) general requirement, 164.308(a)(5)(ii)(A) Security Reminders (addressable), 164.308(a)(5)(ii)(B) Protection from Malicious Software (addressable), 164.308(a)(5)(ii)(C) Log-in Monitoring (addressable), 164.308(a)(5)(ii)(D) Password Management (addressable). ' +
      'SOC 2: CC1.4 (Entity demonstrates a commitment to attract, develop, and retain competent individuals), CC2.2 (Communicating internally). ' +
      'ISO 27001:2022: A.6.3 (Information security awareness, education and training), A.5.4 (Management responsibilities). ' +
      'CIS v8: Control 14 (Security Awareness and Skills Training — 14.1 establish and maintain a security awareness program, 14.2 train workforce members to recognize social engineering attacks, 14.3 train workforce members on authentication best practices, 14.4 train workforce members on data handling best practices, 14.5 train workforce members on causes of unintentional data exposure, 14.6 train workforce members on recognizing and reporting security incidents, 14.7 train workforce on how to identify and report if their enterprise assets have missing security updates, 14.8 train workforce on the dangers of connecting to and transmitting enterprise data over insecure networks, 14.9 conduct role-specific security training).',
    tags: ['security-training', 'awareness', 'phishing', 'social-engineering', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-50/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: [],
    mitreIds: ['T1566', 'T1204'],
    relatedIds: ['COMP-INCIDENT', 'COMP-EMAILSEC'],
    detection: 'Training completion tracking, phishing simulation results, policy acknowledgment records, knowledge assessment scores',
    mitigation: 'Conduct annual security awareness training, run monthly phishing simulations, require policy acknowledgment, provide role-specific training for developers and admins, track completion rates'
  },

  // ──────────────────────────────────────────────────────────
  // 12. Physical Security
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-PHYSICAL',
    domain: 'compliance',
    title: 'Physical Security',
    content:
      'Physical access to systems and facilities containing sensitive data must be controlled and monitored. ' +
      'PCI DSS 4.0: Req 9 (Restrict physical access to cardholder data — 9.1 processes defined, 9.2 physical access controls for sensitive areas, 9.3 physical access for personnel and visitors authorized and managed, 9.4 media physically secured, 9.5 POI devices protected from tampering). ' +
      'HIPAA: 164.310(a)(1) Facility Access Controls — 164.310(a)(2)(i) Contingency Operations (addressable), 164.310(a)(2)(ii) Facility Security Plan (addressable), 164.310(a)(2)(iii) Access Control and Validation Procedures (addressable), 164.310(a)(2)(iv) Maintenance Records (addressable), 164.310(b) Workstation Use, 164.310(c) Workstation Security, 164.310(d)(1) Device and Media Controls. ' +
      'SOC 2: CC6.4 (Physical access controls for facilities and data centers), CC6.5 (Disposal of assets and data). ' +
      'ISO 27001:2022: A.7.1 (Physical security perimeters), A.7.2 (Physical entry), A.7.3 (Securing offices, rooms and facilities), A.7.4 (Physical security monitoring), A.7.5 (Protecting against physical and environmental threats), A.7.6 (Working in secure areas), A.7.7 (Clear desk and clear screen), A.7.8 (Equipment siting and protection). ' +
      'CIS v8: Control 1.1 (Establish and maintain a detailed enterprise asset inventory — includes physical assets).',
    tags: ['physical-security', 'facility-access', 'media-controls', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://www.hhs.gov/hipaa/'
    ],
    cweIds: [],
    mitreIds: ['T1200', 'T1091'],
    relatedIds: ['COMP-ACCESS', 'COMP-ASSET'],
    detection: 'Physical access log review, visitor log audit, badge access analysis, CCTV review, tailgating tests',
    mitigation: 'Implement badge-based access control, deploy CCTV monitoring, maintain visitor logs, use man-traps for high-security areas, escort visitors, shred sensitive documents'
  },

  // ──────────────────────────────────────────────────────────
  // 13. Vendor / Third-Party Risk Management
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-VENDOR',
    domain: 'compliance',
    title: 'Vendor & Third-Party Risk Management',
    content:
      'Third-party and vendor risk must be assessed and managed to ensure supply chain security. ' +
      'PCI DSS 4.0: Req 12.8 (Risk to information assets from third-party relationships is managed — 12.8.1 list of TPSPs maintained, 12.8.2 written agreements maintained, 12.8.3 due diligence performed before engagement, 12.8.4 monitor TPSPs PCI DSS compliance annually, 12.8.5 maintain information about which PCI DSS requirements are managed by each TPSP), Req 12.9 (TPSPs support their customers PCI DSS compliance). ' +
      'HIPAA: 164.308(b)(1) Business Associate Contracts and Other Arrangements — written contracts or arrangements with business associates, 164.314(a) Business Associate Contracts or Other Arrangements. ' +
      'SOC 2: CC9.2 (Entity assesses and manages risks associated with vendors and business partners), CC3.4 (Third-party risk considered in risk assessment). ' +
      'ISO 27001:2022: A.5.19 (Information security in supplier relationships), A.5.20 (Addressing information security within supplier agreements), A.5.21 (Managing information security in the ICT supply chain), A.5.22 (Monitoring, review and change management of supplier services), A.5.23 (Information security for use of cloud services). ' +
      'CIS v8: Control 15 (Service Provider Management — 15.1 establish and maintain an inventory of service providers, 15.2 establish and maintain a service provider management policy, 15.3 classify service providers, 15.4 ensure service provider contracts include security requirements, 15.5 assess service providers, 15.6 monitor service providers, 15.7 securely decommission service providers).',
    tags: ['vendor-risk', 'third-party', 'supply-chain', 'tprm', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-829'],
    mitreIds: ['T1195', 'T1199'],
    relatedIds: ['COMP-RISK', 'COMP-CONTRACTMGMT'],
    detection: 'Vendor inventory review, contract audit, SOC 2/ISO report collection, security questionnaire analysis, continuous monitoring of vendor posture',
    mitigation: 'Maintain vendor inventory, require security assessments before onboarding, include security clauses in contracts, review vendor SOC 2 reports annually, monitor vendor breach notifications, establish right-to-audit clauses'
  },

  // ──────────────────────────────────────────────────────────
  // 14. Asset Management / Inventory
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-ASSET',
    domain: 'compliance',
    title: 'Asset Management & Inventory',
    content:
      'Maintaining an accurate and current inventory of all information assets is foundational to security. ' +
      'PCI DSS 4.0: Req 9.5 (POI device inventories), Req 12.5.1 (Inventory of system components in scope for PCI DSS is maintained and kept current). ' +
      'HIPAA: 164.308(a)(1)(ii)(A) Risk Analysis (requires identifying all ePHI systems), 164.310(d)(1) Device and Media Controls — hardware and electronic media inventory. ' +
      'SOC 2: CC6.1 (Inventory of information assets maintained), CC3.1 (Risk assessment considers asset inventory). ' +
      'ISO 27001:2022: A.5.9 (Inventory of information and other associated assets), A.5.10 (Acceptable use of information and other associated assets), A.5.11 (Return of assets), A.8.1 (User endpoint devices). ' +
      'CIS v8: Control 1 (Inventory and Control of Enterprise Assets — 1.1 establish and maintain a detailed enterprise asset inventory, 1.2 address unauthorized assets, 1.3 utilize a DHCP logging to update the enterprise asset inventory, 1.4 use dynamic host configuration protocol server to update the asset inventory, 1.5 use a passive asset discovery tool), Control 2 (Inventory and Control of Software Assets — 2.1 establish and maintain a software inventory, 2.2 ensure authorized software is currently supported, 2.3 address unauthorized software, 2.4 utilize automated software inventory tools, 2.5 allowlist authorized software, 2.6 allowlist authorized libraries, 2.7 allowlist authorized scripts).',
    tags: ['asset-management', 'inventory', 'cmdb', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/controls/v8'
    ],
    cweIds: [],
    mitreIds: ['T1200', 'T1583'],
    relatedIds: ['COMP-CONFIGMGMT', 'COMP-DATACLASS'],
    detection: 'Asset discovery scanning, CMDB accuracy audit, shadow IT detection, network scanning for unknown devices',
    mitigation: 'Automate asset discovery, maintain centralized CMDB, reconcile inventory quarterly, tag assets with owner and classification, decommission unauthorized assets promptly'
  },

  // ──────────────────────────────────────────────────────────
  // 15. Configuration Management / Hardening
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-CONFIGMGMT',
    domain: 'compliance',
    title: 'Configuration Management & System Hardening',
    content:
      'Systems must be securely configured using industry-accepted hardening standards and baselines. ' +
      'PCI DSS 4.0: Req 2 (Apply secure configurations to all system components — 2.1 processes defined, 2.2 system components configured and managed securely — 2.2.1 configuration standards developed using industry sources like CIS Benchmarks/NIST/SANS, 2.2.2 vendor default accounts managed, 2.2.3 primary functions requiring different security levels managed, 2.2.4 only necessary services/protocols/daemons/functions enabled, 2.2.5 insecure services/protocols secured if present, 2.2.6 system security parameters configured to prevent misuse, 2.2.7 all non-console admin access encrypted). ' +
      'HIPAA: 164.312(a)(1) Access Control (implies hardened configuration of systems processing ePHI), 164.308(a)(1)(ii)(B) Risk Management (implement security measures to reduce risks — includes hardening). ' +
      'SOC 2: CC6.1 (Security configurations implemented), CC7.1 (Configuration change detection), CC8.1 (Changes to configuration managed). ' +
      'ISO 27001:2022: A.8.9 (Configuration management), A.8.19 (Installation of software on operational systems), A.8.27 (Secure system architecture and engineering principles). ' +
      'CIS v8: Control 4 (Secure Configuration of Enterprise Assets and Software — 4.1 establish and maintain a secure configuration process, 4.2 establish and maintain a secure configuration process for network infrastructure, 4.3 configure automatic session locking, 4.4 implement and manage a firewall on servers, 4.5 implement and manage a firewall on end-user devices, 4.6 securely manage enterprise assets and software, 4.7 manage default accounts on enterprise assets and software, 4.8 uninstall or disable unnecessary services, 4.9 configure trusted DNS servers, 4.10 enforce automatic device lockout, 4.11 enforce remote wipe capability, 4.12 separate enterprise workspaces on mobile devices).',
    tags: ['configuration-management', 'hardening', 'cis-benchmarks', 'baselines', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.cisecurity.org/cis-benchmarks/',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-16', 'CWE-1188'],
    mitreIds: ['T1078.001', 'T1562.001'],
    relatedIds: ['COMP-ASSET', 'COMP-CHANGEMGMT', 'COMP-VULN'],
    detection: 'CIS Benchmark scanning, configuration drift detection, golden image comparison, compliance scanning tools',
    mitigation: 'Define secure baselines using CIS Benchmarks, automate configuration deployment (Ansible/Chef/Puppet), monitor for drift, disable unnecessary services and ports, change all default credentials'
  },

  // ──────────────────────────────────────────────────────────
  // 16. Penetration Testing
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-PENTEST',
    domain: 'compliance',
    title: 'Penetration Testing',
    content:
      'Regular penetration testing is required to validate the effectiveness of security controls. ' +
      'PCI DSS 4.0: Req 11.4 (External and internal penetration testing is regularly performed — 11.4.1 methodology defined, 11.4.2 internal pen test at least annually, 11.4.3 external pen test at least annually, 11.4.4 exploitable vulnerabilities corrected and retested, 11.4.5 network segmentation controls tested every 6 months for service providers, 11.4.6 additional pen test requirements for service providers). ' +
      'HIPAA: 164.308(a)(8) Evaluation — periodic technical and nontechnical evaluation (pen testing is a recommended method though not explicitly named). ' +
      'SOC 2: CC4.1 (Monitoring activities evaluate whether controls are effective, including penetration testing), CC7.1 (Detection and monitoring includes penetration tests). ' +
      'ISO 27001:2022: A.8.8 (Management of technical vulnerabilities — pen testing as a validation method), A.5.35 (Independent review of information security — can include pen testing). ' +
      'CIS v8: Control 18 (Penetration Testing — 18.1 establish and maintain a penetration testing program, 18.2 perform periodic external penetration tests, 18.3 remediate penetration test findings, 18.4 validate security measures after each penetration test, 18.5 perform periodic internal penetration tests).',
    tags: ['penetration-testing', 'red-team', 'offensive-security', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://owasp.org/www-project-web-security-testing-guide/'
    ],
    cweIds: [],
    mitreIds: ['T1190', 'T1210', 'T1068'],
    relatedIds: ['COMP-VULN', 'COMP-APPSEC'],
    detection: 'Annual pen test reports, remediation tracking, segmentation test results, red team exercise outcomes',
    mitigation: 'Conduct annual internal and external penetration tests, use qualified testers, remediate findings within defined SLAs, retest after remediation, include application-layer testing'
  },

  // ──────────────────────────────────────────────────────────
  // 17. Risk Assessment
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-RISK',
    domain: 'compliance',
    title: 'Risk Assessment',
    content:
      'Formal, documented risk assessments are a cornerstone requirement across all compliance frameworks. ' +
      'PCI DSS 4.0: Req 12.3 (Risks to the CDE are formally identified, evaluated, and managed — 12.3.1 targeted risk analysis performed for each PCI DSS requirement with flexibility, 12.3.2 targeted risk analysis performed for each customized approach requirement, 12.3.3 cryptographic cipher suites and protocols documented, 12.3.4 hardware and software technologies reviewed at least annually). ' +
      'HIPAA: 164.308(a)(1)(ii)(A) Risk Analysis (required — conduct an accurate and thorough assessment of risks to ePHI), 164.308(a)(1)(ii)(B) Risk Management (implement security measures sufficient to reduce risks to a reasonable and appropriate level). ' +
      'SOC 2: CC3.1 (Entity specifies objectives and identifies risks), CC3.2 (Entity identifies risks to objectives), CC3.3 (Entity considers potential for fraud), CC3.4 (Entity identifies and assesses changes that could significantly impact the system of internal controls), CC4.1 (Entity selects, develops, and performs ongoing evaluations). ' +
      'ISO 27001:2022: Clause 6.1.2 (Information security risk assessment), Clause 6.1.3 (Information security risk treatment), Clause 8.2 (Information security risk assessment — perform at planned intervals), Clause 8.3 (Information security risk treatment). ' +
      'CIS v8: Control 3.7 (Establish and maintain a data classification scheme — risk-based), Implementation Group model itself is risk-based prioritization.',
    tags: ['risk-assessment', 'risk-management', 'risk-analysis', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final',
      'https://www.iso.org/standard/27001'
    ],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['COMP-VULN', 'COMP-VENDOR', 'COMP-INCIDENT'],
    detection: 'Risk register review, risk assessment report analysis, risk treatment plan tracking, residual risk evaluation',
    mitigation: 'Conduct annual enterprise-wide risk assessments, maintain risk register, document risk treatment decisions, assign risk owners, review risk posture quarterly, use quantitative methods where possible'
  },

  // ──────────────────────────────────────────────────────────
  // 18. Data Retention & Disposal
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-RETENTION',
    domain: 'compliance',
    title: 'Data Retention & Disposal',
    content:
      'Data must be retained only as long as necessary and securely disposed of when no longer required. ' +
      'PCI DSS 4.0: Req 3.2 (Storage of account data is kept to a minimum — 3.2.1 data retention and disposal policies, procedures, and processes defined, quarterly process to identify and securely delete stored account data exceeding retention period), Req 9.4 (Media with cardholder data is securely stored, accessed, distributed, and destroyed — 9.4.6 hard-copy materials with cardholder data destroyed, 9.4.7 electronic media with cardholder data destroyed when no longer needed). ' +
      'HIPAA: 164.530(j) Retention and Disposal (retain records for 6 years from date of creation or date last in effect), 164.310(d)(2)(i) Disposal — addressable (policies for final disposition of ePHI and hardware), 164.310(d)(2)(ii) Media Re-use — addressable. ' +
      'SOC 2: CC6.5 (Secure disposal/destruction of data and hardware). ' +
      'ISO 27001:2022: A.8.10 (Information deletion), A.8.12 (Data leakage prevention — includes disposal), A.7.10 (Storage media — secure disposal). ' +
      'CIS v8: Control 3.4 (Enforce data retention), Control 3.5 (Securely dispose of data).',
    tags: ['data-retention', 'data-disposal', 'secure-deletion', 'media-sanitization', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-212', 'CWE-459'],
    mitreIds: ['T1005', 'T1530'],
    relatedIds: ['COMP-DATACLASS', 'COMP-PHYSICAL'],
    detection: 'Retention schedule review, data age analysis, disposal certificate audit, media sanitization verification',
    mitigation: 'Define retention schedules per data type, automate data expiration, use NIST SP 800-88 media sanitization methods, obtain certificates of destruction, audit quarterly for data exceeding retention'
  },

  // ──────────────────────────────────────────────────────────
  // 19. Wireless Security
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-WIRELESS',
    domain: 'compliance',
    title: 'Wireless Security',
    content:
      'Wireless networks must be secured to prevent unauthorized access and eavesdropping. ' +
      'PCI DSS 4.0: Req 1.2.3 (Accurate network diagrams showing wireless networks), Req 2.3 (Wireless environments connected to/accessing the CDE are configured and managed securely — 2.3.1 all wireless vendor defaults changed including WEP keys, default SSIDs, passwords, and SNMP community strings, 2.3.2 wireless encryption keys changed when personnel with knowledge depart), Req 11.2 (Wireless access points are identified and monitored — 11.2.1 authorized and unauthorized wireless access points managed, 11.2.2 quarterly wireless analyzer scans or wireless IDS/IPS deployed). ' +
      'HIPAA: 164.312(e)(1) Transmission Security — applies to wireless transmission of ePHI, 164.312(e)(2)(ii) Encryption (addressable — wireless ePHI transmissions). ' +
      'SOC 2: CC6.1 (Logical access security extends to wireless networks), CC6.6 (System boundary protection — includes wireless). ' +
      'ISO 27001:2022: A.8.20 (Networks security — includes wireless), A.8.21 (Security of network services — includes wireless service agreements). ' +
      'CIS v8: Control 12.6 (Use of encrypted sessions for network management and access — includes wireless management).',
    tags: ['wireless', 'wifi', 'wpa3', 'rogue-ap', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://www.wi-fi.org/discover-wi-fi/security'
    ],
    cweIds: ['CWE-311'],
    mitreIds: ['T1557', 'T1040', 'T1600'],
    relatedIds: ['COMP-NETWORK', 'COMP-ENCRYPT'],
    detection: 'Quarterly wireless scans, rogue AP detection, wireless IDS alerts, WPA configuration review',
    mitigation: 'Use WPA3-Enterprise, segment wireless from CDE, conduct quarterly wireless scans, deploy wireless IDS, disable WPS, change default credentials, maintain wireless network inventory'
  },

  // ──────────────────────────────────────────────────────────
  // 20. Mobile Device Management
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-MDM',
    domain: 'compliance',
    title: 'Mobile Device Management',
    content:
      'Mobile devices accessing sensitive data must be managed, secured, and monitored. ' +
      'PCI DSS 4.0: Req 2.2 (System components are configured and managed securely — includes mobile devices), Req 8.4.2 (MFA for all non-console access to the CDE — includes mobile), Req 12.3.1 (Risk analysis for technologies including mobile). ' +
      'HIPAA: 164.312(a)(2)(iv) Encryption and Decryption (addressable — mobile device encryption for ePHI at rest), 164.312(d) Person or Entity Authentication (mobile device access to ePHI), 164.310(b) Workstation Use (policies applicable to mobile devices used as workstations), 164.310(c) Workstation Security (physical safeguards applicable to mobile). ' +
      'SOC 2: CC6.1 (Logical access controls for mobile access), CC6.7 (Restriction of data movement — mobile transfers), CC6.8 (Controls to prevent/detect unauthorized or malicious software — mobile apps). ' +
      'ISO 27001:2022: A.8.1 (User endpoint devices — includes mobile), A.6.7 (Remote working — mobile device policies). ' +
      'CIS v8: Control 4.11 (Enforce automatic device lockout on portable end-user devices), Control 4.12 (Separate enterprise workspaces on mobile end-user devices), Control 3.6 (Encrypt data on end-user devices).',
    tags: ['mobile-device-management', 'mdm', 'byod', 'endpoint', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final',
      'https://www.cisecurity.org/controls/v8'
    ],
    cweIds: ['CWE-311', 'CWE-921'],
    mitreIds: ['T1458', 'T1474'],
    relatedIds: ['COMP-ENCRYPT', 'COMP-ACCESS', 'COMP-CONFIGMGMT'],
    detection: 'MDM enrollment verification, device compliance checks, jailbreak/root detection, encryption status audit',
    mitigation: 'Deploy MDM/EMM solution, enforce device encryption, require screen lock, enable remote wipe, separate personal/enterprise data, enforce app whitelisting, monitor device compliance'
  },

  // ──────────────────────────────────────────────────────────
  // 21. Cloud Security
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-CLOUD',
    domain: 'compliance',
    title: 'Cloud Security',
    content:
      'Cloud environments require shared responsibility models and cloud-specific security controls. ' +
      'PCI DSS 4.0: Req 12.8 (Third-party service provider management — cloud providers are TPSPs), Req 12.9 (TPSPs acknowledge responsibility), Appendix A1 (Multi-tenant service provider requirements — A1.1 logical separation, A1.2 controls to ensure each customer only accesses own CDE), Req 2.2 (Secure configuration extends to cloud workloads). ' +
      'HIPAA: 164.308(b)(1) Business Associate Contracts (cloud providers are BAs when processing ePHI), 164.312(a)(1) Access Control (applied to cloud-hosted ePHI), 164.312(e)(1) Transmission Security (cloud data in transit). ' +
      'SOC 2: CC6.1 (Logical access controls in cloud environments), CC6.7 (Data transmission/storage restrictions in cloud), CC7.1 (Cloud infrastructure monitoring), CC9.2 (Cloud vendor risk management). ' +
      'ISO 27001:2022: A.5.23 (Information security for use of cloud services), A.5.21 (Managing information security in the ICT supply chain), A.8.26 (Application security requirements — includes cloud-native apps). ' +
      'CIS v8: Control 3.12 (Segment data processing and storage based on sensitivity — cloud workloads), Control 15 (Service Provider Management — covers cloud providers), Control 16 (Application Software Security — includes cloud-deployed applications).',
    tags: ['cloud-security', 'iaas', 'paas', 'saas', 'shared-responsibility', 'cross-framework'],
    severity: 'high',
    references: [
      'https://cloudsecurityalliance.org/research/cloud-controls-matrix/',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-284', 'CWE-16'],
    mitreIds: ['T1530', 'T1537', 'T1580'],
    relatedIds: ['COMP-VENDOR', 'COMP-ENCRYPT', 'COMP-CONFIGMGMT'],
    detection: 'Cloud security posture management (CSPM), cloud configuration audit, shared responsibility matrix review, cloud access security broker (CASB) analysis',
    mitigation: 'Define shared responsibility matrix, enable cloud-native logging (CloudTrail, Azure Monitor, GCP Audit Logs), enforce IAM least privilege, use CSPM tools, encrypt cloud storage, implement cloud workload protection'
  },

  // ──────────────────────────────────────────────────────────
  // 22. Application Security / SDLC
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-APPSEC',
    domain: 'compliance',
    title: 'Application Security & Secure SDLC',
    content:
      'Applications must be developed securely, tested for vulnerabilities, and maintained throughout their lifecycle. ' +
      'PCI DSS 4.0: Req 6 (Develop and maintain secure systems and software — 6.1 processes defined, 6.2 bespoke and custom software developed securely — 6.2.1 secure development training, 6.2.2 at least annually software dev personnel trained, 6.2.3 reviewed prior to release for potential coding vulnerabilities, 6.2.4 software engineering techniques to prevent/mitigate common vulnerabilities), Req 6.3 (Security vulnerabilities identified and addressed), Req 6.4 (Public-facing web applications are protected — 6.4.1 WAF or equivalent for public web apps, 6.4.2 automated technical solution for detection and prevention of web-based attacks). ' +
      'HIPAA: 164.308(a)(1)(ii)(B) Risk Management (includes application risks), 164.312(a)(1) Access Control (application-level access controls), 164.312(c)(1) Integrity (electronic mechanisms to corroborate ePHI not altered — application integrity). ' +
      'SOC 2: CC8.1 (Changes to application code authorized, designed, developed, tested, approved, and implemented), CC7.1 (Application vulnerability management), CC7.5 (Vulnerability remediation includes applications). ' +
      'ISO 27001:2022: A.8.25 (Secure development life cycle), A.8.26 (Application security requirements), A.8.27 (Secure system architecture and engineering principles), A.8.28 (Secure coding), A.8.29 (Security testing in development and acceptance), A.8.30 (Outsourced development), A.8.31 (Separation of development, test and production environments). ' +
      'CIS v8: Control 16 (Application Software Security — 16.1 establish and maintain a secure application development process, 16.2 establish and maintain a process for accepting and addressing software vulnerabilities, 16.3 perform root cause analysis on security vulnerabilities, 16.4 establish and manage an inventory of third-party software components, 16.5 use up-to-date and trusted third-party software components, 16.6 establish and maintain a severity rating system for application vulnerabilities, 16.7 use standard hardening configuration templates for application infrastructure, 16.8 separate production and non-production systems, 16.9 train developers in application security, 16.10 apply secure design principles in application architectures, 16.11 leverage vetted modules or services for application security, 16.12 implement code-level security checks, 16.13 conduct application penetration testing, 16.14 conduct threat modeling).',
    tags: ['application-security', 'sdlc', 'secure-development', 'sast', 'dast', 'cross-framework'],
    severity: 'high',
    references: [
      'https://owasp.org/www-project-application-security-verification-standard/',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-79', 'CWE-89', 'CWE-94', 'CWE-502'],
    mitreIds: ['T1190', 'T1059'],
    relatedIds: ['COMP-CHANGEMGMT', 'COMP-PENTEST', 'COMP-VULN'],
    detection: 'SAST/DAST scanning, code review audit, OWASP Top 10 assessment, SCA analysis, threat model review',
    mitigation: 'Integrate SAST/DAST into CI/CD, conduct peer code reviews, implement threat modeling, train developers on OWASP Top 10, deploy WAF for public apps, use SCA for third-party components'
  },

  // ──────────────────────────────────────────────────────────
  // 23. Malware Protection
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-MALWARE',
    domain: 'compliance',
    title: 'Malware Protection',
    content:
      'Anti-malware defenses must be deployed, maintained, and monitored across all systems. ' +
      'PCI DSS 4.0: Req 5 (Protect all systems and networks from malicious software — 5.1 processes defined, 5.2 malicious software is prevented or detected and addressed — 5.2.1 anti-malware solution deployed on all systems commonly affected by malware, 5.2.2 anti-malware solution performs periodic scans and active/real-time scans, 5.2.3 systems not commonly affected by malware periodically evaluated, 5.3 anti-malware mechanisms and processes are active, maintained, and monitored — 5.3.1 anti-malware solution kept current, 5.3.2 anti-malware solution performs automatic updates, 5.3.3 anti-malware solution running actively, 5.3.4 audit logs for anti-malware solution enabled, 5.3.5 anti-malware solution cannot be disabled by users unless justified and time-limited, 5.4 anti-phishing mechanisms protect users). ' +
      'HIPAA: 164.308(a)(5)(ii)(B) Protection from Malicious Software (addressable — procedures for guarding against, detecting, and reporting malicious software). ' +
      'SOC 2: CC6.8 (Controls to prevent or detect unauthorized or malicious software), CC7.1 (Detection of malicious code). ' +
      'ISO 27001:2022: A.8.7 (Protection against malware). ' +
      'CIS v8: Control 10 (Malware Defenses — 10.1 deploy and maintain anti-malware software, 10.2 configure automatic anti-malware signature updates, 10.3 disable autorun and autoplay for removable media, 10.4 configure automatic anti-malware scanning of removable media, 10.5 enable anti-exploitation features, 10.6 centrally manage anti-malware software, 10.7 use behavior-based anti-malware software).',
    tags: ['malware', 'antivirus', 'edr', 'endpoint-protection', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.pcisecuritystandards.org/',
      'https://www.cisecurity.org/controls/v8'
    ],
    cweIds: ['CWE-506', 'CWE-507'],
    mitreIds: ['T1059', 'T1204', 'T1547', 'T1566'],
    relatedIds: ['COMP-CONFIGMGMT', 'COMP-EMAILSEC'],
    detection: 'Anti-malware deployment audit, signature update verification, detection event analysis, endpoint protection coverage review',
    mitigation: 'Deploy EDR/XDR on all endpoints and servers, enable automatic signature updates, centralize management, enable behavior-based detection, block autorun on removable media, implement application whitelisting'
  },

  // ──────────────────────────────────────────────────────────
  // 24. Email Security
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-EMAILSEC',
    domain: 'compliance',
    title: 'Email Security',
    content:
      'Email systems must be secured against phishing, spoofing, malware delivery, and data exfiltration. ' +
      'PCI DSS 4.0: Req 5.4 (Anti-phishing mechanisms protect users against phishing attacks — 5.4.1 processes and automated mechanisms to detect and protect personnel against phishing), Req 4.2.1 (Certificates used for PAN transmission over open networks are valid — applicable to email-based PAN transmission). ' +
      'HIPAA: 164.312(e)(1) Transmission Security (email containing ePHI must be encrypted), 164.312(e)(2)(ii) Encryption (addressable — email encryption for ePHI), 164.308(a)(5)(ii)(A) Security Reminders (addressable — includes email-borne threats). ' +
      'SOC 2: CC6.6 (System boundary protection — includes email gateway security), CC6.8 (Controls to prevent malicious software — includes email filtering). ' +
      'ISO 27001:2022: A.5.14 (Information transfer — includes email security policies), A.8.7 (Protection against malware — includes email-borne malware). ' +
      'CIS v8: Control 9 (Email and Web Browser Protections — 9.1 ensure use of only fully supported browsers and email clients, 9.2 use DNS filtering services, 9.3 maintain and enforce network-based URL filters, 9.4 restrict unnecessary or unauthorized browser and email client extensions, 9.5 implement DMARC, 9.6 block unnecessary file types, 9.7 deploy and maintain email server anti-malware protections).',
    tags: ['email-security', 'phishing', 'dmarc', 'spf', 'dkim', 'cross-framework'],
    severity: 'medium',
    references: [
      'https://www.cisecurity.org/controls/v8',
      'https://dmarc.org/'
    ],
    cweIds: [],
    mitreIds: ['T1566.001', 'T1566.002', 'T1534'],
    relatedIds: ['COMP-MALWARE', 'COMP-TRAINING'],
    detection: 'DMARC/SPF/DKIM record verification, email gateway log analysis, phishing simulation results, blocked attachment reports',
    mitigation: 'Implement DMARC with p=reject, configure SPF and DKIM, deploy email gateway with advanced threat protection, block dangerous attachment types, enable URL rewriting/sandboxing, encrypt email containing sensitive data'
  },

  // ──────────────────────────────────────────────────────────
  // 25. Key Management
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-KEYMGMT',
    domain: 'compliance',
    title: 'Cryptographic Key Management',
    content:
      'Cryptographic keys must be securely generated, stored, distributed, rotated, and destroyed throughout their lifecycle. ' +
      'PCI DSS 4.0: Req 3.6 (Cryptographic keys used to protect stored account data are secured — 3.6.1 procedures defined for protecting cryptographic keys, 3.6.1.1 additional key management requirements for service providers, 3.6.1.2 secret/private keys for encrypting stored account data accessible to fewest custodians, 3.6.1.3 access to cleartext cryptographic key components restricted to fewest custodians, 3.6.1.4 cryptographic keys stored in fewest locations), Req 3.7 (Where cryptography is used to protect stored account data, key management processes and procedures cover — 3.7.1 key generation procedures, 3.7.2 secure key distribution, 3.7.3 secure key storage, 3.7.4 key changes at cryptoperiod end, 3.7.5 retirement/replacement of compromised keys, 3.7.6 split knowledge and dual control for manual key management, 3.7.7 prevention of unauthorized key substitution, 3.7.8 key custodian acknowledgment of responsibilities, 3.7.9 all previous requirements for all keys used to protect stored data). ' +
      'HIPAA: 164.312(a)(2)(iv) Encryption and Decryption (addressable — implies key management), 164.312(e)(2)(ii) Encryption (addressable — implies management of keys for transmission encryption). ' +
      'SOC 2: CC6.1 (Cryptographic key management processes supporting encryption controls). ' +
      'ISO 27001:2022: A.8.24 (Use of cryptography — includes key management policies and procedures). ' +
      'CIS v8: Control 3.11 (Encrypt sensitive data at rest — implies key management), Control 3.10 (Encrypt sensitive data in transit — implies key management).',
    tags: ['key-management', 'cryptography', 'hsm', 'kms', 'cross-framework'],
    severity: 'critical',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-320', 'CWE-321', 'CWE-326'],
    mitreIds: ['T1552.004', 'T1588.004'],
    relatedIds: ['COMP-ENCRYPT', 'COMP-ACCESS'],
    detection: 'Key lifecycle audit, key storage review, HSM/KMS configuration review, key rotation schedule verification, key custodian access review',
    mitigation: 'Use FIPS 140-2/3 validated HSMs or cloud KMS, enforce key rotation per NIST SP 800-57 cryptoperiods, implement split knowledge and dual control, maintain key inventory, revoke compromised keys immediately, automate key lifecycle management'
  },

  // ──────────────────────────────────────────────────────────
  // 26. Privacy & Data Subject Rights
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-PRIVACY',
    domain: 'compliance',
    title: 'Privacy & Data Subject Rights',
    content:
      'Organizations must protect personal data and honor data subject rights per applicable regulations. ' +
      'PCI DSS 4.0: Req 3 (Protect stored account data — data minimization and protection), Req 12.1.1 (Information security policy addresses all PCI DSS requirements). ' +
      'HIPAA: 164.502 Uses and Disclosures (minimum necessary), 164.524 Individual Access (right of individuals to access their PHI), 164.526 Amendment (right to amend PHI), 164.528 Accounting of Disclosures, 164.530(a) Privacy Notice Requirements, 164.522 Right to Request Privacy Protection. ' +
      'SOC 2: P1.0 (Privacy criteria — notice and communication of objectives), P2.0 (Choice and consent), P3.0 (Collection), P4.0 (Use, retention, and disposal), P5.0 (Access), P6.0 (Disclosure and notification), P7.0 (Quality), P8.0 (Monitoring and enforcement). ' +
      'ISO 27001:2022: A.5.34 (Privacy and protection of PII), A.5.33 (Protection of records). ' +
      'CIS v8: Control 3 (Data Protection — overlaps with privacy through data minimization, classification, and retention).',
    tags: ['privacy', 'data-subject-rights', 'pii', 'phi', 'consent', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.hhs.gov/hipaa/for-professionals/privacy/',
      'https://www.aicpa.org/soc2'
    ],
    cweIds: ['CWE-359'],
    mitreIds: ['T1005', 'T1530'],
    relatedIds: ['COMP-DATACLASS', 'COMP-RETENTION'],
    detection: 'Privacy impact assessment, data subject request response time tracking, consent management audit, data inventory validation',
    mitigation: 'Implement data minimization, honor data subject requests within regulatory timelines, maintain privacy notices, obtain and record consent, conduct privacy impact assessments, appoint data protection officer if required'
  },

  // ──────────────────────────────────────────────────────────
  // 27. Secure Remote Access
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-REMOTEACCESS',
    domain: 'compliance',
    title: 'Secure Remote Access',
    content:
      'Remote access to systems and networks must be secured with strong authentication and encrypted channels. ' +
      'PCI DSS 4.0: Req 2.2.7 (All non-console administrative access encrypted using strong cryptography), Req 8.4.3 (MFA for all remote access to the CDE for both personnel and third parties), Req 12.3.1 (Risk analysis for technologies enabling remote access). ' +
      'HIPAA: 164.312(e)(1) Transmission Security (remote access sessions transmitting ePHI must be encrypted), 164.312(d) Person or Entity Authentication (remote users must be authenticated). ' +
      'SOC 2: CC6.1 (Remote access authentication and authorization controls), CC6.2 (Registration and authorization prior to remote access credential issuance), CC6.6 (Boundary protections for remote access points). ' +
      'ISO 27001:2022: A.6.7 (Remote working), A.8.5 (Secure authentication — includes remote access), A.8.20 (Networks security — remote access channels). ' +
      'CIS v8: Control 6.4 (Require MFA for remote network access), Control 12.7 (Ensure remote devices utilize a VPN and are connecting to an enterprise AAA infrastructure).',
    tags: ['remote-access', 'vpn', 'zero-trust', 'mfa', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-46/rev-2/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-287', 'CWE-319'],
    mitreIds: ['T1133', 'T1021'],
    relatedIds: ['COMP-AUTH', 'COMP-NETWORK', 'COMP-ENCRYPT'],
    detection: 'Remote access session audit, VPN configuration review, MFA enforcement verification, remote access log analysis',
    mitigation: 'Require MFA for all remote access, use VPN or zero-trust network access, encrypt all remote sessions, log and monitor remote access, restrict remote access to authorized personnel, implement session timeouts'
  },

  // ──────────────────────────────────────────────────────────
  // 28. Security Governance & Policy
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-GOVERNANCE',
    domain: 'compliance',
    title: 'Security Governance & Policy Management',
    content:
      'Documented security policies, governance structures, and management commitment are foundational requirements. ' +
      'PCI DSS 4.0: Req 12 (Support information security with organizational policies and programs — 12.1 information security policy established, published, maintained, 12.1.1 overall security policy established, 12.1.2 security policy reviewed annually, 12.1.3 security policy clearly defines roles and responsibilities, 12.1.4 responsibility for information security formally assigned to a CISO or equivalent, 12.4 PCI DSS compliance managed). ' +
      'HIPAA: 164.308(a)(1)(i) Security Management Process, 164.308(a)(2) Assigned Security Responsibility (designate security official), 164.316(a) Policies and Procedures (required — maintain reasonable and appropriate policies), 164.316(b) Documentation — 164.316(b)(2)(i) Time Limit — retain for 6 years. ' +
      'SOC 2: CC1.1 (Entity demonstrates commitment to integrity and ethical values), CC1.2 (Board of directors demonstrates independence from management and exercises oversight), CC1.3 (Management establishes structures, reporting lines, and appropriate authorities), CC1.4 (Commitment to attract, develop, and retain competent individuals), CC1.5 (Individuals held accountable for security responsibilities), CC2.1 (Information quality objectives). ' +
      'ISO 27001:2022: Clause 5.1 (Leadership and commitment), Clause 5.2 (Information security policy), Clause 5.3 (Organizational roles, responsibilities and authorities), A.5.1 (Policies for information security), A.5.2 (Information security roles and responsibilities), A.5.3 (Segregation of duties), A.5.4 (Management responsibilities). ' +
      'CIS v8: Governance implied across all controls — organizational policy is a prerequisite for implementation of any control.',
    tags: ['governance', 'policy', 'ciso', 'security-program', 'cross-framework'],
    severity: 'high',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/standard/27001'
    ],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['COMP-RISK', 'COMP-TRAINING'],
    detection: 'Policy inventory review, policy update currency check, RACI matrix validation, board reporting frequency audit',
    mitigation: 'Establish comprehensive security policy framework, designate CISO or equivalent, review policies annually, define clear RACI for security functions, report security posture to board, maintain policy exceptions register'
  },

  // ──────────────────────────────────────────────────────────
  // 29. Secure Software Supply Chain
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-SUPPLYCHAIN',
    domain: 'compliance',
    title: 'Secure Software Supply Chain',
    content:
      'Third-party software, libraries, and components must be inventoried, vetted, and monitored for vulnerabilities. ' +
      'PCI DSS 4.0: Req 6.3.2 (Inventory of bespoke and custom software, and third-party software components incorporated into bespoke and custom software, maintained to facilitate vulnerability and patch management), Req 6.2.4 (Software engineering techniques or other methods to prevent or mitigate common software attacks — includes supply chain concerns). ' +
      'HIPAA: 164.308(a)(1)(ii)(A) Risk Analysis (supply chain risks must be assessed), 164.308(b)(1) Business Associate Contracts (software vendors as BAs). ' +
      'SOC 2: CC9.2 (Vendor and business partner risk management — includes software suppliers), CC8.1 (Changes including third-party components managed). ' +
      'ISO 27001:2022: A.5.19 (Information security in supplier relationships), A.5.21 (Managing information security in the ICT supply chain), A.8.30 (Outsourced development — includes third-party code). ' +
      'CIS v8: Control 16.4 (Establish and manage an inventory of third-party software components), Control 16.5 (Use up-to-date and trusted third-party software components), Control 16.11 (Leverage vetted modules or services for application security components).',
    tags: ['supply-chain', 'sbom', 'third-party-components', 'sca', 'cross-framework'],
    severity: 'high',
    references: [
      'https://www.cisa.gov/sbom',
      'https://owasp.org/www-project-dependency-check/'
    ],
    cweIds: ['CWE-829', 'CWE-1104', 'CWE-1035'],
    mitreIds: ['T1195.001', 'T1195.002'],
    relatedIds: ['COMP-VENDOR', 'COMP-APPSEC', 'COMP-VULN'],
    detection: 'SCA scanning, SBOM generation and analysis, dependency vulnerability monitoring, typosquat detection',
    mitigation: 'Generate and maintain SBOM, run SCA tools in CI/CD, monitor dependencies for CVEs, pin dependency versions, use private registries, verify package integrity with checksums/signatures'
  },

  // ──────────────────────────────────────────────────────────
  // 30. Identity & Privilege Management
  // ──────────────────────────────────────────────────────────
  {
    id: 'COMP-IDENTITY',
    domain: 'compliance',
    title: 'Identity & Privilege Management',
    content:
      'Privileged accounts and identities require enhanced controls including just-in-time access, session monitoring, and regular certification. ' +
      'PCI DSS 4.0: Req 7.2 (Access to system components and data is appropriately defined and assigned — 7.2.1 access control model defined, 7.2.2 access assigned based on job classification and function, 7.2.3 required privileges approved by authorized personnel, 7.2.4 all user accounts and related access privileges reviewed semi-annually, 7.2.5 all application and system accounts and related access privileges assigned and managed, 7.2.6 all user access to query repositories of stored cardholder data restricted), Req 8.6 (Use of application and system accounts managed — 8.6.1 interactive use managed/exception-based, 8.6.2 passwords/passphrases for system/application accounts not hard-coded, 8.6.3 passwords/passphrases protected against misuse). ' +
      'HIPAA: 164.312(a)(2)(i) Unique User Identification (required), 164.308(a)(3) Workforce Security — 164.308(a)(3)(ii)(A) Authorization and/or Supervision (addressable), 164.308(a)(3)(ii)(B) Workforce Clearance Procedure (addressable), 164.308(a)(3)(ii)(C) Termination Procedures (addressable), 164.308(a)(4) Information Access Management. ' +
      'SOC 2: CC6.2 (Registration and authorization of new users), CC6.3 (Authorization-based access), CC6.1 (Logical access security — privileged access controls). ' +
      'ISO 27001:2022: A.5.15 (Access control), A.5.16 (Identity management), A.5.17 (Authentication information), A.5.18 (Access rights — provisioning, review, removal, adjustment), A.8.2 (Privileged access rights), A.8.3 (Information access restriction). ' +
      'CIS v8: Control 5 (Account Management — 5.1 establish and maintain an account inventory, 5.2 use unique passwords, 5.3 disable dormant accounts, 5.4 restrict administrator privileges to dedicated administrator accounts, 5.5 establish and maintain an inventory of service accounts, 5.6 centralize account management), Control 6 (Access Control Management — 6.1 establish an access granting process, 6.2 establish an access revoking process).',
    tags: ['identity-management', 'privileged-access', 'pam', 'iam', 'joiner-mover-leaver', 'cross-framework'],
    severity: 'critical',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-63/3/final',
      'https://www.pcisecuritystandards.org/'
    ],
    cweIds: ['CWE-250', 'CWE-269', 'CWE-798'],
    mitreIds: ['T1078.002', 'T1078.004', 'T1134'],
    relatedIds: ['COMP-ACCESS', 'COMP-AUTH'],
    detection: 'Privileged account inventory, access certification review, dormant account scan, service account audit, privilege escalation testing',
    mitigation: 'Deploy PAM solution, implement just-in-time access, conduct semi-annual access reviews, disable dormant accounts after 90 days, eliminate shared accounts, separate admin and user accounts, automate joiner-mover-leaver workflows'
  }
];

module.exports = { COMPLIANCE_MATRIX };
