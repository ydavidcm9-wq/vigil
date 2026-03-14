'use strict';

const NIST_CONTROLS = [
  // ═══════════════════════════════════════════════════════════════
  // NIST CSF 2.0 Functions (6 core functions)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-CSF-GV',
    domain: 'nist',
    title: 'GOVERN (GV) — NIST CSF 2.0',
    content: 'Establishes and monitors the organization\'s cybersecurity risk management strategy, expectations, and policy. Subcategories: Organizational Context (GV.OC), Risk Management Strategy (GV.RM), Roles/Responsibilities/Authorities (GV.RR), Policy (GV.PO), Oversight (GV.OV), Cybersecurity Supply Chain Risk Management (GV.SC). Key activities: Define risk appetite and tolerance, establish cybersecurity governance structure, integrate cybersecurity with enterprise risk management, assign accountability at executive level, manage supply chain cybersecurity risk.',
    tags: ['governance', 'risk-management', 'policy', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-ID', 'NIST-CSF-PR'],
    detection: 'Policy review, governance audit, risk assessment evaluation, board reporting review',
    mitigation: 'Formal cybersecurity program with executive sponsorship, board-level reporting, documented risk appetite statement, RACI matrix for cybersecurity roles'
  },
  {
    id: 'NIST-CSF-ID',
    domain: 'nist',
    title: 'IDENTIFY (ID) — NIST CSF 2.0',
    content: 'Understand the organization\'s current cybersecurity risks. Subcategories: Asset Management (ID.AM), Risk Assessment (ID.RA), Improvement (ID.IM). Key activities: Maintain inventories of hardware, software, data, and services; identify critical business processes and their cybersecurity dependencies; conduct risk assessments regularly; use threat intelligence; identify improvement opportunities from assessments and incidents. This function drives prioritization of effort across all other functions.',
    tags: ['asset-management', 'risk-assessment', 'inventory', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-GV', 'NIST-CSF-PR', 'NIST-RA-3', 'NIST-RA-5'],
    detection: 'Asset inventory audit, risk register review, vulnerability assessment, business impact analysis',
    mitigation: 'CMDB implementation, automated asset discovery, regular risk assessments, threat modeling program, continuous improvement process'
  },
  {
    id: 'NIST-CSF-PR',
    domain: 'nist',
    title: 'PROTECT (PR) — NIST CSF 2.0',
    content: 'Use safeguards to prevent or reduce cybersecurity risk. Subcategories: Identity Management/Authentication/Access Control (PR.AA), Awareness and Training (PR.AT), Data Security (PR.DS), Platform Security (PR.PS), Technology Infrastructure Resilience (PR.IR). Key activities: Manage identities and credentials, enforce least privilege, train workforce, protect data at rest and in transit, harden platforms, maintain resilient architecture. This is the largest protective surface area in any security program.',
    tags: ['access-control', 'encryption', 'hardening', 'training', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-ID', 'NIST-CSF-DE', 'NIST-AC-1', 'NIST-SC-8'],
    detection: 'Access control review, encryption audit, training records, configuration baseline comparison',
    mitigation: 'Defense-in-depth strategy, MFA everywhere, encryption at rest and in transit, security awareness program, CIS benchmark hardening'
  },
  {
    id: 'NIST-CSF-DE',
    domain: 'nist',
    title: 'DETECT (DE) — NIST CSF 2.0',
    content: 'Find and analyze possible cybersecurity attacks and compromises. Subcategories: Continuous Monitoring (DE.CM), Adverse Event Analysis (DE.AE). Key activities: Monitor networks, endpoints, and environments for anomalies; collect and correlate security event data; analyze events to identify incidents; integrate threat intelligence into detection; tune detection to minimize false positives while maintaining coverage. Detection speed directly impacts breach cost.',
    tags: ['monitoring', 'detection', 'siem', 'ids', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-RS', 'NIST-SI-4', 'NIST-AU-6'],
    detection: 'SIEM effectiveness review, detection coverage mapping, mean-time-to-detect metrics, alert triage analysis',
    mitigation: 'SIEM deployment with 24/7 monitoring, EDR on all endpoints, network detection, threat hunting program, detection engineering pipeline'
  },
  {
    id: 'NIST-CSF-RS',
    domain: 'nist',
    title: 'RESPOND (RS) — NIST CSF 2.0',
    content: 'Take action regarding a detected cybersecurity incident. Subcategories: Incident Management (RS.MA), Incident Analysis (RS.AN), Incident Response Reporting and Communication (RS.CO), Incident Mitigation (RS.MI). Key activities: Execute incident response plans, triage and analyze incidents, contain threats, eradicate root cause, communicate with stakeholders, coordinate with external parties (law enforcement, ISACs), document lessons learned.',
    tags: ['incident-response', 'containment', 'eradication', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-DE', 'NIST-CSF-RC', 'NIST-IR-1', 'NIST-IR-4'],
    detection: 'IR plan testing results, tabletop exercise outcomes, incident timeline analysis, communication effectiveness review',
    mitigation: 'Documented IR plan with playbooks, trained IR team, regular tabletop exercises, pre-established communication templates, retainer with IR firm'
  },
  {
    id: 'NIST-CSF-RC',
    domain: 'nist',
    title: 'RECOVER (RC) — NIST CSF 2.0',
    content: 'Restore assets and operations affected by a cybersecurity incident. Subcategories: Incident Recovery Plan Execution (RC.RP), Incident Recovery Communication (RC.CO). Key activities: Execute recovery plans, restore systems to known-good state, verify integrity of restored systems, communicate recovery status to stakeholders, conduct post-incident review, incorporate lessons learned into recovery planning. Recovery time directly impacts business continuity.',
    tags: ['recovery', 'business-continuity', 'disaster-recovery', 'framework', 'csf'],
    severity: 'info',
    references: ['https://www.nist.gov/cyberframework'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CSF-RS', 'NIST-CP-2', 'NIST-CP-10'],
    detection: 'BCP/DR test results, RTO/RPO achievement metrics, backup integrity verification, recovery exercise outcomes',
    mitigation: 'Tested disaster recovery plans, immutable backups, defined RTO/RPO targets, regular recovery exercises, crisis communication plan'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Access Control (AC)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-AC-1',
    domain: 'nist',
    title: 'AC-1: Access Control Policy and Procedures',
    content: 'Organization develops, documents, disseminates access control policy addressing purpose, scope, roles, responsibilities, management commitment, coordination, and compliance. Procedures facilitate implementation of the policy and associated controls. Review/update frequency: policy annually, procedures annually or after significant changes. This is the foundational control for the entire AC family.',
    tags: ['access-control', 'policy', 'administrative'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-1/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-AC-2', 'NIST-AC-3'],
    detection: 'Policy document review, compliance audit, gap analysis against AC family',
    mitigation: 'Document and maintain access control policy with regular reviews, align with organizational risk appetite'
  },
  {
    id: 'NIST-AC-2',
    domain: 'nist',
    title: 'AC-2: Account Management',
    content: 'Define and manage system account types (individual, shared, group, service, temporary, guest). Lifecycle: create, enable, modify, disable, remove. Require manager authorization for account requests. Review accounts periodically (at least annually). Disable accounts when no longer required, after inactivity period, or upon personnel termination. Enhancements include automated account management (AC-2(1)), automated temporary/emergency disabling (AC-2(2)), and role-based access (AC-2(7)).',
    tags: ['access-control', 'account-management', 'lifecycle', 'provisioning'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/'],
    cweIds: ['CWE-284', 'CWE-269'],
    mitreIds: ['T1078', 'T1136'],
    relatedIds: ['NIST-AC-3', 'NIST-AC-6', 'NIST-IA-4'],
    detection: 'Account review audit, orphan account scan, privilege escalation monitoring, access recertification results',
    mitigation: 'Automated provisioning/deprovisioning, regular access reviews, integration with HR offboarding, privileged account vaulting'
  },
  {
    id: 'NIST-AC-3',
    domain: 'nist',
    title: 'AC-3: Access Enforcement',
    content: 'Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies. Mechanisms include ACLs, RBAC, ABAC, MAC. System must deny access by default and only grant access per explicit authorization. Enhancements: role-based (AC-3(7)), attribute-based (AC-3(13)). Every access decision should be logged for accountability.',
    tags: ['access-control', 'authorization', 'rbac', 'enforcement'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/'],
    cweIds: ['CWE-285', 'CWE-862', 'CWE-863'],
    mitreIds: ['T1068', 'T1548'],
    relatedIds: ['NIST-AC-2', 'NIST-AC-6'],
    detection: 'Access control testing, authorization bypass testing, privilege escalation testing',
    mitigation: 'Implement deny-by-default, use RBAC/ABAC, enforce at all layers (network, application, data), test authorization regularly'
  },
  {
    id: 'NIST-AC-6',
    domain: 'nist',
    title: 'AC-6: Least Privilege',
    content: 'Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks. Enhancements: authorize access to security functions (AC-6(1)), non-privileged access for non-security functions (AC-6(2)), network access to privileged commands (AC-6(3)), separate processing domains (AC-6(4)), privileged accounts (AC-6(5)), audit use of privilege (AC-6(9)), prohibit privileged access to non-security functions (AC-6(10)). Least privilege is consistently the most impactful access control.',
    tags: ['access-control', 'least-privilege', 'authorization', 'zero-trust'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/'],
    cweIds: ['CWE-269', 'CWE-250'],
    mitreIds: ['T1078', 'T1548'],
    relatedIds: ['NIST-AC-2', 'NIST-AC-3', 'NIST-AC-17'],
    detection: 'Privilege analysis, access review, admin account audit, excessive permission scan',
    mitigation: 'Role mining, just-in-time access, PAM solutions, regular privilege reviews, break-glass procedures for emergency access'
  },
  {
    id: 'NIST-AC-17',
    domain: 'nist',
    title: 'AC-17: Remote Access',
    content: 'Establish and document usage restrictions, configuration requirements, and connection requirements for each type of remote access allowed. Authorize each type of remote access prior to allowing connections. Route remote access through managed access control points. Enhancements: automated monitoring/control (AC-17(1)), cryptographic protection (AC-17(2)), managed access points (AC-17(3)). Critical for hybrid/remote workforce security.',
    tags: ['access-control', 'remote-access', 'vpn', 'zero-trust'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-17/'],
    cweIds: ['CWE-284'],
    mitreIds: ['T1133', 'T1021'],
    relatedIds: ['NIST-AC-3', 'NIST-SC-8', 'NIST-IA-2'],
    detection: 'Remote access log review, VPN configuration audit, unauthorized remote access detection',
    mitigation: 'VPN with MFA, zero trust network access (ZTNA), session monitoring, managed access points, split tunneling controls'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Audit and Accountability (AU)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-AU-2',
    domain: 'nist',
    title: 'AU-2: Event Logging',
    content: 'Identify events the system must be capable of logging in support of audit. Coordinate event logging with other organizations sharing audit/log information. Types: login/logout, failed access, privilege use, system events, admin actions, data access, policy changes. Update event list based on threat assessment. Must balance completeness with performance and storage. Correlate with AU-3 (content of audit records) and AU-6 (review/analysis).',
    tags: ['audit', 'logging', 'events', 'accountability'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/'],
    cweIds: ['CWE-778'],
    mitreIds: ['T1562.002'],
    relatedIds: ['NIST-AU-3', 'NIST-AU-6', 'NIST-SI-4'],
    detection: 'Logging coverage assessment, event source inventory, log gap analysis',
    mitigation: 'Define auditable events list, centralized logging, ensure coverage of authentication, authorization, admin actions, and data access events'
  },
  {
    id: 'NIST-AU-3',
    domain: 'nist',
    title: 'AU-3: Content of Audit Records',
    content: 'Audit records must contain: what type of event, when it occurred, where it occurred, source of event, outcome (success/fail), identity of subjects/objects involved. Additional detail as needed: full text of commands, email addresses, file names, network addresses. Records must be detailed enough to reconstruct a timeline. Enhancement AU-3(1): additional audit information for investigation support.',
    tags: ['audit', 'logging', 'forensics', 'accountability'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/au/au-3/'],
    cweIds: ['CWE-778', 'CWE-779'],
    mitreIds: [],
    relatedIds: ['NIST-AU-2', 'NIST-AU-6'],
    detection: 'Audit record completeness review, log format validation, timestamp consistency check',
    mitigation: 'Structured logging format (JSON), include who/what/when/where/outcome, UTC timestamps, correlation IDs across services'
  },
  {
    id: 'NIST-AU-6',
    domain: 'nist',
    title: 'AU-6: Audit Record Review, Analysis, and Reporting',
    content: 'Review and analyze audit records for indications of inappropriate or unusual activity. Report findings to appropriate personnel. Frequency: at least weekly for privileged actions, daily for critical systems. Enhancements: automated review (AU-6(1)), correlate audit repositories (AU-6(3)), central review and analysis (AU-6(4)), integrate with vulnerability scanning (AU-6(6)). SIEM platforms are the primary enabler.',
    tags: ['audit', 'siem', 'analysis', 'monitoring'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/au/au-6/'],
    cweIds: [],
    mitreIds: ['T1070'],
    relatedIds: ['NIST-AU-2', 'NIST-AU-3', 'NIST-SI-4'],
    detection: 'SIEM alert review, log analysis process assessment, analyst workload metrics',
    mitigation: 'SIEM with correlation rules, automated alerting, analyst playbooks, regular tuning of detection rules, threat hunting cadence'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Awareness and Training (AT)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-AT-2',
    domain: 'nist',
    title: 'AT-2: Literacy Training and Awareness',
    content: 'Provide security and privacy literacy training to all users (including managers and senior executives). Training content: recognizing social engineering, phishing, insider threats; password hygiene; physical security awareness; incident reporting procedures; acceptable use. Frequency: upon hire and at least annually. Enhancements: practical exercises (AT-2(1)), insider threat awareness (AT-2(2)), social engineering/mining (AT-2(3)). Measure effectiveness through phishing simulations.',
    tags: ['training', 'awareness', 'phishing', 'social-engineering'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/at/at-2/'],
    cweIds: [],
    mitreIds: ['T1566', 'T1204'],
    relatedIds: ['NIST-AT-3', 'NIST-PM-13'],
    detection: 'Training completion rates, phishing simulation results, security incident rates from user behavior',
    mitigation: 'Annual security awareness training, quarterly phishing simulations, role-based training for privileged users, gamified learning platform'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Configuration Management (CM)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-CM-2',
    domain: 'nist',
    title: 'CM-2: Baseline Configuration',
    content: 'Develop, document, and maintain a current baseline configuration of the information system under configuration control. Baseline includes: OS/firmware versions, patch levels, application configurations, network topology, security settings. Review and update baselines at least annually and when system changes occur. Enhancements: automated support (CM-2(2)), retention of previous configs (CM-2(3)). Use CIS Benchmarks or DISA STIGs as starting points.',
    tags: ['configuration', 'baseline', 'hardening', 'change-management'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-2/'],
    cweIds: ['CWE-16'],
    mitreIds: ['T1574'],
    relatedIds: ['NIST-CM-6', 'NIST-CM-7', 'NIST-CM-8'],
    detection: 'Configuration drift detection, baseline compliance scanning, change detection',
    mitigation: 'Infrastructure as Code, automated compliance scanning, CIS Benchmarks/DISA STIGs, configuration drift monitoring, golden image management'
  },
  {
    id: 'NIST-CM-6',
    domain: 'nist',
    title: 'CM-6: Configuration Settings',
    content: 'Establish and document mandatory configuration settings for IT products using the most restrictive mode consistent with operational requirements. Implement settings. Identify, document, and approve any deviations. Monitor and control changes. Use automated mechanisms to centrally manage, apply, and verify. Focus on: disabling unnecessary services, enforcing strong ciphers, removing default credentials, applying security headers, closing unnecessary ports.',
    tags: ['configuration', 'hardening', 'security-settings', 'compliance'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-6/'],
    cweIds: ['CWE-16', 'CWE-1188'],
    mitreIds: ['T1574', 'T1505'],
    relatedIds: ['NIST-CM-2', 'NIST-CM-7'],
    detection: 'Configuration audit, compliance scanning, hardening assessment, default credential scan',
    mitigation: 'Group Policy/MDM enforcement, Ansible/Chef/Puppet automation, continuous compliance monitoring, deviation approval workflow'
  },
  {
    id: 'NIST-CM-7',
    domain: 'nist',
    title: 'CM-7: Least Functionality',
    content: 'Configure the system to provide only essential capabilities. Disable or remove unnecessary functions, ports, protocols, services, and software. Enhancements: periodic review (CM-7(1)), prevent unauthorized software execution (CM-7(2)), authorized software allow-listing (CM-7(4)), authorized software deny-listing (CM-7(5)). Attack surface reduction is the goal — every unnecessary service is an additional risk.',
    tags: ['configuration', 'attack-surface', 'hardening', 'minimization'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-7/'],
    cweIds: ['CWE-16'],
    mitreIds: ['T1543', 'T1505'],
    relatedIds: ['NIST-CM-2', 'NIST-CM-6', 'NIST-CM-8'],
    detection: 'Port scanning, service enumeration, installed software inventory, unnecessary service detection',
    mitigation: 'Application allowlisting, disable unnecessary services, remove unused software, close unnecessary ports, regular attack surface review'
  },
  {
    id: 'NIST-CM-8',
    domain: 'nist',
    title: 'CM-8: System Component Inventory',
    content: 'Develop and document an inventory of system components that accurately reflects the system, includes all components within the authorization boundary, is at the level of granularity necessary for tracking, and includes information for component accountability. Enhancements: updates during installations/removals (CM-8(1)), automated maintenance (CM-8(2)), automated detection of unauthorized components (CM-8(3)). You cannot protect what you do not know about.',
    tags: ['asset-management', 'inventory', 'configuration', 'visibility'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-8/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CM-2', 'NIST-CSF-ID'],
    detection: 'Asset discovery scans, CMDB accuracy audit, shadow IT detection, rogue device identification',
    mitigation: 'Automated asset discovery, CMDB integration, network access control (NAC), regular reconciliation, agent-based inventory'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Contingency Planning (CP)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-CP-2',
    domain: 'nist',
    title: 'CP-2: Contingency Plan',
    content: 'Develop a contingency plan that identifies essential missions and business functions, provides recovery objectives (RTO/RPO), defines restoration priorities, includes roles and responsibilities, addresses maintaining essential functions during disruption, is reviewed and approved by designated officials. Update plan based on changes, exercises, lessons learned. Coordinate with incident response (IR) plans. Enhancements: coordinate with related plans (CP-2(1)), capacity planning (CP-2(2)).',
    tags: ['contingency', 'business-continuity', 'disaster-recovery', 'planning'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cp/cp-2/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CP-4', 'NIST-CP-9', 'NIST-CP-10', 'NIST-CSF-RC'],
    detection: 'Plan completeness review, RTO/RPO validation, plan currency audit, exercise results',
    mitigation: 'Documented BCP/DR plan, defined RTO/RPO per system, executive approval, annual review, integration with IR plan'
  },
  {
    id: 'NIST-CP-9',
    domain: 'nist',
    title: 'CP-9: System Backup',
    content: 'Conduct backups of user-level, system-level, and security-related information at frequency consistent with RTO/RPO. Protect backup confidentiality, integrity, and availability. Test backups regularly for reliability and information integrity. Enhancements: testing for reliability/integrity (CP-9(1)), test restoration using sampling (CP-9(2)), separate storage for critical information (CP-9(3)), cryptographic protection (CP-9(8)). The 3-2-1 rule: 3 copies, 2 media types, 1 offsite.',
    tags: ['backup', 'recovery', 'data-protection', 'resilience'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cp/cp-9/'],
    cweIds: [],
    mitreIds: ['T1490', 'T1485'],
    relatedIds: ['NIST-CP-2', 'NIST-CP-10'],
    detection: 'Backup completion verification, restoration test results, backup integrity checks, offsite storage audit',
    mitigation: '3-2-1 backup strategy, immutable backups, encrypted backup storage, regular restoration testing, air-gapped backup copies for ransomware resilience'
  },
  {
    id: 'NIST-CP-10',
    domain: 'nist',
    title: 'CP-10: System Recovery and Reconstitution',
    content: 'Provide for the recovery and reconstitution of the system to a known state within defined RTO after disruption, compromise, or failure. Recovery includes restoring system functionality. Reconstitution includes rebuilding to operational capability. Enhancements: transaction recovery (CP-10(2)), compensating security controls during recovery (CP-10(4)). Reconstitution must verify system integrity before returning to production.',
    tags: ['recovery', 'reconstitution', 'resilience', 'disaster-recovery'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/cp/cp-10/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-CP-2', 'NIST-CP-9', 'NIST-CSF-RC'],
    detection: 'Recovery exercise results, reconstitution time measurement, integrity verification post-recovery',
    mitigation: 'Documented recovery procedures, infrastructure as code for rapid rebuild, integrity verification checklists, staged recovery environments'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Identification and Authentication (IA)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-IA-2',
    domain: 'nist',
    title: 'IA-2: Identification and Authentication (Organizational Users)',
    content: 'Uniquely identify and authenticate organizational users. Each user must have a unique identifier — no shared accounts for individual accountability. Enhancements: MFA for network access (IA-2(1)), MFA for local access (IA-2(2)), MFA for remote access (IA-2(6)), network access to non-privileged accounts (IA-2(8)). MFA factors: something you know + something you have + something you are. Phishing-resistant MFA (FIDO2/WebAuthn) is the gold standard.',
    tags: ['authentication', 'mfa', 'identity', 'access-control'],
    severity: 'critical',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-2/'],
    cweIds: ['CWE-287', 'CWE-306'],
    mitreIds: ['T1078', 'T1110'],
    relatedIds: ['NIST-IA-4', 'NIST-IA-5', 'NIST-AC-2'],
    detection: 'MFA enrollment audit, authentication method review, shared account detection, single-factor access identification',
    mitigation: 'Phishing-resistant MFA (FIDO2/WebAuthn), unique user IDs, eliminate shared accounts, SSO integration, conditional access policies'
  },
  {
    id: 'NIST-IA-4',
    domain: 'nist',
    title: 'IA-4: Identifier Management',
    content: 'Manage system identifiers by: receiving authorization before assigning an individual, group, role, service, or device identifier; selecting identifiers that identify the entity; assigning to the intended entity; preventing reuse for a defined period; disabling after defined period of inactivity. Enhancements: prohibit account identifiers as public identifiers (IA-4(4)), dynamic management (IA-4(9)). Identifiers must be unique within the organizational scope.',
    tags: ['identity', 'identifier-management', 'lifecycle', 'access-control'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-4/'],
    cweIds: ['CWE-287'],
    mitreIds: ['T1078'],
    relatedIds: ['NIST-IA-2', 'NIST-IA-5', 'NIST-AC-2'],
    detection: 'Identifier uniqueness audit, inactive identifier review, identifier reuse check',
    mitigation: 'Centralized identity management (IdP), automated lifecycle management, identifier naming standards, regular inactive identifier purge'
  },
  {
    id: 'NIST-IA-5',
    domain: 'nist',
    title: 'IA-5: Authenticator Management',
    content: 'Manage system authenticators (passwords, tokens, certificates, biometrics) by: verifying identity before issuing; establishing initial authenticator content; ensuring sufficient strength; distributing securely; storing securely (hashed/encrypted); establishing min/max lifetime; changing on compromise; protecting against unauthorized disclosure/modification. Enhancements: password-based (IA-5(1)) requirements include minimum length 12+ chars, complexity, composition rules, dictionary checks. Use password managers.',
    tags: ['authentication', 'password', 'credentials', 'secrets-management'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-5/'],
    cweIds: ['CWE-521', 'CWE-256', 'CWE-522'],
    mitreIds: ['T1110', 'T1003'],
    relatedIds: ['NIST-IA-2', 'NIST-IA-4'],
    detection: 'Password policy compliance check, credential strength audit, leaked credential monitoring, certificate expiration monitoring',
    mitigation: 'Minimum 12-char passwords, password manager mandate, bcrypt/scrypt hashing, credential leak monitoring, certificate rotation automation'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Incident Response (IR)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-IR-1',
    domain: 'nist',
    title: 'IR-1: Incident Response Policy and Procedures',
    content: 'Develop, document, disseminate incident response policy addressing purpose, scope, roles, responsibilities, management commitment, coordination, and compliance. Procedures facilitate implementation. Define what constitutes an incident vs event. Establish incident severity levels and escalation criteria. Review/update annually. The policy sets the authority for the IR team to act decisively during incidents.',
    tags: ['incident-response', 'policy', 'governance'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ir/ir-1/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-IR-4', 'NIST-IR-6', 'NIST-IR-8', 'NIST-CSF-RS'],
    detection: 'Policy review, IR authority validation, escalation matrix review',
    mitigation: 'Documented IR policy with executive approval, defined incident classification scheme, clear escalation paths, legal/communications integration'
  },
  {
    id: 'NIST-IR-4',
    domain: 'nist',
    title: 'IR-4: Incident Handling',
    content: 'Implement incident handling capability including preparation, detection and analysis, containment, eradication, and recovery. Coordinate incident handling with contingency planning. Enhancements: automated handling processes (IR-4(1)), dynamic reconfiguration (IR-4(2)), continuity of operations (IR-4(3)), information correlation (IR-4(4)), insider threats (IR-4(6)), integrated response plan (IR-4(11)). NIST SP 800-61r2 provides detailed guidance. Speed of containment is the primary driver of breach cost reduction.',
    tags: ['incident-response', 'handling', 'containment', 'eradication'],
    severity: 'critical',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ir/ir-4/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-IR-1', 'NIST-IR-5', 'NIST-IR-6', 'NIST-CSF-RS'],
    detection: 'IR process maturity assessment, mean-time-to-contain metrics, incident timeline review',
    mitigation: 'Documented playbooks per incident type, SOAR platform, pre-approved containment actions, evidence preservation procedures, post-incident reviews'
  },
  {
    id: 'NIST-IR-6',
    domain: 'nist',
    title: 'IR-6: Incident Reporting',
    content: 'Require personnel to report suspected incidents to the organizational incident response capability. Report incidents to external authorities as required (CISA, law enforcement, regulators, GDPR DPAs). Enhancements: automated reporting (IR-6(1)), vulnerabilities related to incidents (IR-6(2)). Timelines: CISA 72-hour reporting for critical infrastructure, GDPR 72-hour notification. Establish clear internal reporting channels to reduce friction.',
    tags: ['incident-response', 'reporting', 'notification', 'compliance'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ir/ir-6/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-IR-1', 'NIST-IR-4'],
    detection: 'Reporting timeline audit, regulatory notification compliance check, reporting channel accessibility assessment',
    mitigation: 'Easy-access reporting mechanism, defined regulatory notification timelines, pre-drafted notification templates, designated external reporting contacts'
  },
  {
    id: 'NIST-IR-8',
    domain: 'nist',
    title: 'IR-8: Incident Response Plan',
    content: 'Develop an incident response plan that: provides a roadmap for implementing IR capability; describes structure and organization of IR capability; provides a high-level approach to how IR fits within the organization; defines reportable incidents; addresses metrics for measuring IR capability; defines resources and management support needed. Review/revise/distribute plan at least annually and after incidents. The plan is the strategic document; playbooks are the tactical documents.',
    tags: ['incident-response', 'planning', 'documentation', 'governance'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ir/ir-8/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-IR-1', 'NIST-IR-4', 'NIST-CP-2'],
    detection: 'Plan currency review, metrics collection assessment, resource adequacy evaluation',
    mitigation: 'Comprehensive IR plan with playbooks, annual review cycle, post-incident plan updates, defined metrics (MTTD, MTTC, MTTR), executive sponsorship'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Maintenance (MA)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-MA-2',
    domain: 'nist',
    title: 'MA-2: Controlled Maintenance',
    content: 'Schedule, document, and review records of maintenance and repairs on system components. Control maintenance activities whether on-site or remote. Require approval for maintenance tools brought into facility. Check media containing diagnostics/test programs for malicious code before use. Verify security controls still function after maintenance. Maintenance windows should be coordinated with change management and monitored for unauthorized changes.',
    tags: ['maintenance', 'change-management', 'operations'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ma/ma-2/'],
    cweIds: [],
    mitreIds: ['T1195'],
    relatedIds: ['NIST-MA-4', 'NIST-CM-6'],
    detection: 'Maintenance log review, unauthorized maintenance detection, post-maintenance security validation',
    mitigation: 'Scheduled maintenance windows, approval workflow, post-maintenance verification, maintenance activity logging, tool inspection procedures'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Media Protection (MP)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-MP-6',
    domain: 'nist',
    title: 'MP-6: Media Sanitization',
    content: 'Sanitize system media prior to disposal, release, or reuse using approved methods. Methods by media type: clear (logical overwrite), purge (degaussing, cryptographic erase), destroy (shredding, incineration, pulverization). NIST SP 800-88r1 Guidelines for Media Sanitization provides detailed guidance. For SSDs, cryptographic erase or physical destruction is required — overwriting is unreliable due to wear leveling. Document sanitization actions including method, date, personnel, and media identifier.',
    tags: ['media-protection', 'sanitization', 'disposal', 'data-destruction'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/mp/mp-6/'],
    cweIds: ['CWE-226'],
    mitreIds: [],
    relatedIds: ['NIST-MP-6'],
    detection: 'Sanitization record audit, disposed media tracking, sanitization verification',
    mitigation: 'NIST 800-88 compliant sanitization, certificates of destruction, crypto-erase for SSDs, contracted secure destruction for physical media'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Physical and Environmental Protection (PE)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-PE-3',
    domain: 'nist',
    title: 'PE-3: Physical Access Control',
    content: 'Enforce physical access authorizations at entry/exit points by verifying individual access authorizations before granting access, controlling ingress/egress with physical access devices (badge readers, locks) or guards. Maintain physical access audit logs. Control access to areas containing information systems. Escort visitors and monitor visitor activity. Secure keys, combinations, and card access devices. Enhancements: system access (PE-3(1)), facility/areas (PE-3(2)). Physical security is the foundation — bypass physical controls and all logical controls are moot.',
    tags: ['physical-security', 'access-control', 'facility', 'environmental'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/pe/pe-3/'],
    cweIds: [],
    mitreIds: ['T1200'],
    relatedIds: ['NIST-PE-6', 'NIST-AC-3'],
    detection: 'Physical access log review, badge reader audit, visitor log review, tailgating assessment',
    mitigation: 'Badge access control systems, visitor management procedures, CCTV monitoring, anti-tailgating controls, regular access list review'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Planning (PL)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-PL-2',
    domain: 'nist',
    title: 'PL-2: System Security and Privacy Plans',
    content: 'Develop security and privacy plans that: describe the operational context, define current controls and planned enhancements, provide a system overview, describe authorization boundary, identify data types processed. Plans reviewed and approved by authorizing officials. Update upon significant changes. Plans serve as the primary agreement between system owner and authorizing official. They define the security posture baseline for the system.',
    tags: ['planning', 'documentation', 'authorization', 'governance'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/pl/pl-2/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-RA-3', 'NIST-CSF-GV'],
    detection: 'Plan currency review, authorization status verification, control implementation assessment',
    mitigation: 'System security plan (SSP) for each system, annual review, authorizing official approval, integration with risk assessment findings'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Program Management (PM)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-PM-9',
    domain: 'nist',
    title: 'PM-9: Risk Management Strategy',
    content: 'Develop a comprehensive risk management strategy that: defines risk assumptions, constraints, risk tolerance, and priorities/trade-offs; addresses how risks will be identified, assessed, responded to, and monitored; is reviewed and updated at least annually. The strategy should specify acceptable risk levels per system categorization and guide consistent risk-based decision making across the organization. Integrates with NIST RMF (SP 800-37) and ERM frameworks.',
    tags: ['risk-management', 'strategy', 'governance', 'program-management'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/pm/pm-9/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-RA-3', 'NIST-CSF-GV'],
    detection: 'Risk strategy review, risk tolerance validation, risk decision consistency analysis',
    mitigation: 'Documented risk management strategy, defined risk appetite/tolerance, consistent risk assessment methodology, regular strategy review'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Personnel Security (PS)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-PS-3',
    domain: 'nist',
    title: 'PS-3: Personnel Screening',
    content: 'Screen individuals prior to authorizing access to the system. Screening criteria include: position risk designation, background investigations appropriate to risk level, rescreening at defined frequency. Individuals in higher-risk positions require more thorough screening. Screening must comply with applicable laws, regulations, and policies. Enhancements: classified information (PS-3(1)), formal indoctrination (PS-3(2)). Insider threat starts with hiring — screening is the first line of defense.',
    tags: ['personnel-security', 'screening', 'background-check', 'insider-threat'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ps/ps-3/'],
    cweIds: [],
    mitreIds: ['T1078'],
    relatedIds: ['NIST-PS-4', 'NIST-PS-5'],
    detection: 'Screening completion verification, rescreening currency check, position risk designation review',
    mitigation: 'Risk-based screening levels, background check policy, rescreening intervals, third-party screening for contractors'
  },
  {
    id: 'NIST-PS-4',
    domain: 'nist',
    title: 'PS-4: Personnel Termination',
    content: 'Upon termination: disable system access within defined timeframe (same day for involuntary), retrieve all security-related organizational property (badges, keys, tokens, laptops, mobile devices), conduct exit interview covering security topics, notify relevant personnel of termination. Enhancements: post-employment requirements (PS-4(1)), automated actions (PS-4(2)). Delayed deprovisioning is one of the most common insider threat enablers.',
    tags: ['personnel-security', 'termination', 'offboarding', 'access-revocation'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ps/ps-4/'],
    cweIds: ['CWE-284'],
    mitreIds: ['T1078'],
    relatedIds: ['NIST-PS-3', 'NIST-PS-5', 'NIST-AC-2'],
    detection: 'Offboarding process audit, access revocation timing review, property return verification',
    mitigation: 'Automated deprovisioning linked to HR, same-day access revocation, asset recovery checklist, exit interview procedure, NDA/IP acknowledgment'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Risk Assessment (RA)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-RA-3',
    domain: 'nist',
    title: 'RA-3: Risk Assessment',
    content: 'Conduct risk assessments that: identify threats to and vulnerabilities in the system; determine likelihood and magnitude of harm from unauthorized access, use, disclosure, disruption, modification, or destruction; prioritize risks; document results. Reassess risks when significant changes occur, new threat information emerges, or at defined frequency (at least annually). Use established methodologies: NIST SP 800-30, FAIR, OCTAVE. Risk = Likelihood x Impact. Enhancements: supply chain risk (RA-3(1)), threat hunting (RA-3(4)).',
    tags: ['risk-assessment', 'threat-analysis', 'vulnerability', 'risk-management'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ra/ra-3/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-RA-5', 'NIST-PM-9', 'NIST-CSF-ID'],
    detection: 'Risk assessment currency review, threat model validation, risk register completeness check',
    mitigation: 'Annual risk assessments, defined risk methodology, threat modeling per system, risk register maintenance, risk-based control selection'
  },
  {
    id: 'NIST-RA-5',
    domain: 'nist',
    title: 'RA-5: Vulnerability Monitoring and Scanning',
    content: 'Monitor and scan for vulnerabilities at defined frequency and when new vulnerabilities are identified. Use vulnerability scanning tools and techniques. Analyze scan results and remediate legitimate vulnerabilities within defined timelines based on risk ranking. Share vulnerability information with other organizations to gain awareness. Timelines (common SLAs): Critical 15 days, High 30 days, Medium 90 days, Low 180 days. Enhancements: update tool capability (RA-5(1)), privileged access scanning (RA-5(5)), automated trend analysis (RA-5(6)).',
    tags: ['vulnerability-management', 'scanning', 'remediation', 'risk-assessment'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/ra/ra-5/'],
    cweIds: [],
    mitreIds: ['T1190', 'T1203'],
    relatedIds: ['NIST-RA-3', 'NIST-SI-2', 'NIST-CM-8'],
    detection: 'Vulnerability scan coverage, scan frequency compliance, remediation SLA tracking, false positive rate',
    mitigation: 'Continuous vulnerability scanning, risk-based remediation SLAs, authenticated scanning, integration with patch management, vulnerability exception process'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — System and Services Acquisition (SA)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-SA-8',
    domain: 'nist',
    title: 'SA-8: Security and Privacy Engineering Principles',
    content: 'Apply security and privacy engineering principles in the specification, design, development, implementation, and modification of the system. Principles include: least privilege, defense in depth, fail-safe defaults, separation of duties, minimize attack surface, economy of mechanism, complete mediation, least common mechanism, psychological acceptability. Apply throughout SDLC. Security by design is dramatically cheaper than bolt-on security — fixing in production costs 100x more than in design.',
    tags: ['secure-development', 'engineering', 'sdlc', 'design-principles'],
    severity: 'medium',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sa/sa-8/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-SA-11', 'NIST-SA-15'],
    detection: 'Security architecture review, design review, threat modeling results, secure coding assessment',
    mitigation: 'Security requirements in design phase, threat modeling, secure coding standards, security architecture review board, shift-left security program'
  },
  {
    id: 'NIST-SA-11',
    domain: 'nist',
    title: 'SA-11: Developer Testing and Evaluation',
    content: 'Require developers to create and implement a security assessment plan. Include: unit testing, integration testing, system testing, regression testing. Perform flaw remediation, SAST, DAST, fuzz testing, and code review. Enhancements: static analysis (SA-11(1)), threat modeling (SA-11(2)), dynamic analysis (SA-11(5)), attack surface review (SA-11(6)), manual code review (SA-11(4)). Automated security testing in CI/CD is the minimum bar.',
    tags: ['secure-development', 'testing', 'sast', 'dast', 'code-review'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sa/sa-11/'],
    cweIds: [],
    mitreIds: [],
    relatedIds: ['NIST-SA-8', 'NIST-SA-15'],
    detection: 'Security testing coverage, SAST/DAST results, code review completion rate, CI/CD security gate pass rate',
    mitigation: 'SAST in CI/CD pipeline, DAST in staging, peer code review with security focus, dependency scanning, pre-commit hooks for secrets detection'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — System and Communications Protection (SC)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-SC-7',
    domain: 'nist',
    title: 'SC-7: Boundary Protection',
    content: 'Monitor and control communications at external managed interfaces and key internal boundaries. Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks. Connect to external networks only through managed interfaces with boundary protection devices. Enhancements: deny by default/allow by exception (SC-7(5)), prevent split tunneling (SC-7(7)), route to authenticated proxy (SC-7(8)). Network segmentation limits blast radius.',
    tags: ['network-security', 'firewall', 'segmentation', 'boundary-protection'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-7/'],
    cweIds: ['CWE-284'],
    mitreIds: ['T1046', 'T1090'],
    relatedIds: ['NIST-SC-8', 'NIST-AC-17'],
    detection: 'Firewall rule review, network segmentation verification, DMZ architecture assessment, boundary device configuration audit',
    mitigation: 'Next-gen firewalls, micro-segmentation, DMZ architecture, deny-by-default rules, regular firewall rule review, zero trust network architecture'
  },
  {
    id: 'NIST-SC-8',
    domain: 'nist',
    title: 'SC-8: Transmission Confidentiality and Integrity',
    content: 'Protect the confidentiality and integrity of transmitted information. Enhancements: cryptographic protection (SC-8(1)), pre/post transmission handling (SC-8(2)). Use TLS 1.2+ for all web traffic, IPsec or WireGuard for site-to-site, SSH for admin access. Disable deprecated protocols (SSL 3.0, TLS 1.0/1.1). Implement certificate pinning for critical connections. Mutual TLS (mTLS) for service-to-service communication in microservices.',
    tags: ['encryption', 'tls', 'transport-security', 'data-in-transit'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-8/'],
    cweIds: ['CWE-319', 'CWE-311'],
    mitreIds: ['T1557', 'T1040'],
    relatedIds: ['NIST-SC-7', 'NIST-SC-13', 'NIST-SC-28'],
    detection: 'TLS configuration scan, protocol version audit, cipher suite assessment, certificate validation check',
    mitigation: 'TLS 1.3 preferred / 1.2 minimum, strong cipher suites, HSTS headers, certificate management, disable weak protocols, mTLS for service mesh'
  },
  {
    id: 'NIST-SC-13',
    domain: 'nist',
    title: 'SC-13: Cryptographic Protection',
    content: 'Determine the required cryptographic protections and implement cryptography in accordance with applicable laws, policies, and standards. Use FIPS 140-3 validated cryptographic modules for federal systems. Key algorithms: AES-256 for symmetric encryption, RSA-2048+ or ECDSA P-256+ for asymmetric, SHA-256+ for hashing. Avoid: DES, 3DES, MD5, SHA-1, RC4. Plan for post-quantum cryptography (NIST PQC standards). Cryptographic agility — ability to swap algorithms without major refactoring.',
    tags: ['cryptography', 'encryption', 'hashing', 'key-management'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-13/'],
    cweIds: ['CWE-327', 'CWE-326'],
    mitreIds: [],
    relatedIds: ['NIST-SC-8', 'NIST-SC-28'],
    detection: 'Cryptographic algorithm inventory, weak cipher detection, FIPS compliance validation, key length audit',
    mitigation: 'AES-256 for data, RSA-2048+/ECDSA for keys, SHA-256+ for hashing, FIPS 140-3 modules, crypto inventory, PQC migration planning'
  },
  {
    id: 'NIST-SC-28',
    domain: 'nist',
    title: 'SC-28: Protection of Information at Rest',
    content: 'Protect the confidentiality and integrity of information at rest. Apply to: databases, file systems, backups, removable media, mobile devices. Methods: full-disk encryption (FDE), database transparent data encryption (TDE), file-level encryption, application-level encryption. Key management is critical — encryption is only as strong as key management. Enhancements: cryptographic protection (SC-28(1)), offline storage (SC-28(2)). Cloud: use customer-managed keys (CMK) over provider-managed when possible.',
    tags: ['encryption', 'data-at-rest', 'key-management', 'data-protection'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-28/'],
    cweIds: ['CWE-311', 'CWE-312'],
    mitreIds: ['T1005', 'T1530'],
    relatedIds: ['NIST-SC-8', 'NIST-SC-13'],
    detection: 'Encryption coverage audit, unencrypted data scan, key management review, cloud storage encryption verification',
    mitigation: 'FDE on all endpoints, database encryption, encrypted backups, HSM for key management, customer-managed keys in cloud, data classification-driven encryption'
  },

  // ═══════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — System and Information Integrity (SI)
  // ═══════════════════════════════════════════════════════════════

  {
    id: 'NIST-SI-2',
    domain: 'nist',
    title: 'SI-2: Flaw Remediation',
    content: 'Identify, report, and correct system flaws. Install security-relevant software and firmware updates within defined timeframes. Test updates for effectiveness and potential side effects before installation in production. Incorporate flaw remediation into configuration management. Timelines: critical patches within 15 days, high within 30 days, medium within 90 days. Enhancements: automated flaw remediation (SI-2(2)), time to remediate/benchmarks (SI-2(3)), automated patch management (SI-2(5)). Emergency patches may bypass normal change management with retrospective approval.',
    tags: ['patch-management', 'flaw-remediation', 'vulnerability', 'maintenance'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/si/si-2/'],
    cweIds: [],
    mitreIds: ['T1190', 'T1203'],
    relatedIds: ['NIST-RA-5', 'NIST-CM-6'],
    detection: 'Patch compliance rate, mean-time-to-patch, missing patch identification, SLA compliance tracking',
    mitigation: 'Automated patch management (WSUS, SCCM, Intune), risk-based patching priority, test environment, emergency patch process, compensating controls for delayed patches'
  },
  {
    id: 'NIST-SI-3',
    domain: 'nist',
    title: 'SI-3: Malicious Code Protection',
    content: 'Implement malicious code protection mechanisms at system entry and exit points and at workstations and servers. Update malicious code protection mechanisms when new releases are available. Configure for real-time scanning with automatic updates. Address receipt of false positives and resulting impact on system availability. Modern approach: EDR/XDR over traditional AV. Enhancements: central management (SI-3(1)), automatic updates (SI-3(2)), non-signature-based detection (SI-3(4)). Behavioral analysis catches what signatures miss.',
    tags: ['malware-protection', 'antivirus', 'edr', 'endpoint-security'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/si/si-3/'],
    cweIds: [],
    mitreIds: ['T1204', 'T1059', 'T1055'],
    relatedIds: ['NIST-SI-4', 'NIST-SI-8'],
    detection: 'EDR coverage verification, signature update currency, detection rate assessment, endpoint protection gaps',
    mitigation: 'EDR/XDR on all endpoints, behavioral analysis enabled, automatic signature updates, application allowlisting, email attachment sandboxing'
  },
  {
    id: 'NIST-SI-4',
    domain: 'nist',
    title: 'SI-4: System Monitoring',
    content: 'Monitor the system to detect: attacks and indicators of potential attacks, unauthorized local/network/remote connections, system anomalies. Deploy monitoring devices strategically to collect essential information. Identify unauthorized use of the system. Heighten monitoring during elevated threat periods. Enhancements: system-wide IDS (SI-4(2)), automated real-time alerts (SI-4(5)), inbound and outbound communications traffic (SI-4(4)), wireless intrusion detection (SI-4(14)), correlate monitoring information (SI-4(16)). Layer: NIDS + HIDS + SIEM + EDR for comprehensive coverage.',
    tags: ['monitoring', 'ids', 'network-security', 'threat-detection'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/si/si-4/'],
    cweIds: [],
    mitreIds: ['T1040', 'T1071'],
    relatedIds: ['NIST-AU-6', 'NIST-SI-3', 'NIST-CSF-DE'],
    detection: 'Monitoring coverage assessment, alert volume analysis, detection gap identification, false positive rate measurement',
    mitigation: 'SIEM deployment, network IDS/IPS, endpoint detection, NetFlow analysis, DNS monitoring, cloud workload protection, 24/7 SOC coverage'
  },
  {
    id: 'NIST-SI-7',
    domain: 'nist',
    title: 'SI-7: Software, Firmware, and Information Integrity',
    content: 'Employ integrity verification tools to detect unauthorized changes to software, firmware, and information. Enhancements: integrity checks (SI-7(1)), automated notifications of integrity violations (SI-7(2)), centrally managed integrity tools (SI-7(5)), integration of detection and response (SI-7(7)), auditing of integrity violations (SI-7(8)). Methods: file integrity monitoring (FIM), code signing, secure boot, supply chain verification. FIM on critical system files, configurations, and binaries is essential for detecting compromise.',
    tags: ['integrity', 'file-integrity-monitoring', 'code-signing', 'supply-chain'],
    severity: 'high',
    references: ['https://csf.tools/reference/nist-sp-800-53/r5/si/si-7/'],
    cweIds: ['CWE-354', 'CWE-494'],
    mitreIds: ['T1195', 'T1554'],
    relatedIds: ['NIST-SI-4', 'NIST-CM-6'],
    detection: 'FIM alerts, code signature verification, secure boot validation, hash comparison against known-good baselines',
    mitigation: 'File integrity monitoring (OSSEC, Tripwire), code signing enforcement, secure boot enabled, SBOM management, supply chain verification'
  }
];

module.exports = { NIST_CONTROLS };
