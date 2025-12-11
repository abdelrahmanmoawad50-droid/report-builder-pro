// OWASP Web Security Testing Guide (WSTG) Test Cases
// Based on OWASP WSTG v4.2

export interface TestCase {
  id: string;
  name: string;
  category: string;
}

export const WSTG_TEST_CASES: TestCase[] = [
  // Information Gathering
  { id: 'WSTG-INFO-01', name: 'Conduct Search Engine Discovery', category: 'Information Gathering' },
  { id: 'WSTG-INFO-02', name: 'Fingerprint Web Server', category: 'Information Gathering' },
  { id: 'WSTG-INFO-03', name: 'Review Webserver Metafiles', category: 'Information Gathering' },
  { id: 'WSTG-INFO-04', name: 'Enumerate Applications on Webserver', category: 'Information Gathering' },
  { id: 'WSTG-INFO-05', name: 'Review Webpage Content', category: 'Information Gathering' },
  { id: 'WSTG-INFO-06', name: 'Identify Application Entry Points', category: 'Information Gathering' },
  { id: 'WSTG-INFO-07', name: 'Map Execution Paths', category: 'Information Gathering' },
  { id: 'WSTG-INFO-08', name: 'Fingerprint Web Application Framework', category: 'Information Gathering' },
  { id: 'WSTG-INFO-09', name: 'Fingerprint Web Application', category: 'Information Gathering' },
  { id: 'WSTG-INFO-10', name: 'Map Application Architecture', category: 'Information Gathering' },

  // Configuration and Deployment Management
  { id: 'WSTG-CONF-01', name: 'Test Network Infrastructure', category: 'Configuration Management' },
  { id: 'WSTG-CONF-02', name: 'Test Application Platform Configuration', category: 'Configuration Management' },
  { id: 'WSTG-CONF-03', name: 'Test File Extensions Handling', category: 'Configuration Management' },
  { id: 'WSTG-CONF-04', name: 'Review Old Backup Files', category: 'Configuration Management' },
  { id: 'WSTG-CONF-05', name: 'Enumerate Infrastructure Interfaces', category: 'Configuration Management' },
  { id: 'WSTG-CONF-06', name: 'Test HTTP Methods', category: 'Configuration Management' },
  { id: 'WSTG-CONF-07', name: 'Test HTTP Strict Transport Security', category: 'Configuration Management' },
  { id: 'WSTG-CONF-08', name: 'Test RIA Cross Domain Policy', category: 'Configuration Management' },
  { id: 'WSTG-CONF-09', name: 'Test File Permission', category: 'Configuration Management' },
  { id: 'WSTG-CONF-10', name: 'Test for Subdomain Takeover', category: 'Configuration Management' },
  { id: 'WSTG-CONF-11', name: 'Test Cloud Storage', category: 'Configuration Management' },

  // Identity Management
  { id: 'WSTG-IDNT-01', name: 'Test Role Definitions', category: 'Identity Management' },
  { id: 'WSTG-IDNT-02', name: 'Test User Registration Process', category: 'Identity Management' },
  { id: 'WSTG-IDNT-03', name: 'Test Account Provisioning Process', category: 'Identity Management' },
  { id: 'WSTG-IDNT-04', name: 'Test Account Enumeration', category: 'Identity Management' },
  { id: 'WSTG-IDNT-05', name: 'Test Weak Username Policy', category: 'Identity Management' },

  // Authentication
  { id: 'WSTG-ATHN-01', name: 'Test Credentials Over Encrypted Channel', category: 'Authentication' },
  { id: 'WSTG-ATHN-02', name: 'Test Default Credentials', category: 'Authentication' },
  { id: 'WSTG-ATHN-03', name: 'Test Weak Lock Out Mechanism', category: 'Authentication' },
  { id: 'WSTG-ATHN-04', name: 'Test Bypassing Authentication Schema', category: 'Authentication' },
  { id: 'WSTG-ATHN-05', name: 'Test Vulnerable Remember Password', category: 'Authentication' },
  { id: 'WSTG-ATHN-06', name: 'Test Browser Cache Weaknesses', category: 'Authentication' },
  { id: 'WSTG-ATHN-07', name: 'Test Weak Password Policy', category: 'Authentication' },
  { id: 'WSTG-ATHN-08', name: 'Test Weak Security Question/Answer', category: 'Authentication' },
  { id: 'WSTG-ATHN-09', name: 'Test Weak Password Change Functions', category: 'Authentication' },
  { id: 'WSTG-ATHN-10', name: 'Test Weaker Authentication in Alternative Channel', category: 'Authentication' },

  // Authorization
  { id: 'WSTG-ATHZ-01', name: 'Test Directory Traversal', category: 'Authorization' },
  { id: 'WSTG-ATHZ-02', name: 'Test Bypassing Authorization Schema', category: 'Authorization' },
  { id: 'WSTG-ATHZ-03', name: 'Test Privilege Escalation', category: 'Authorization' },
  { id: 'WSTG-ATHZ-04', name: 'Test Insecure Direct Object References', category: 'Authorization' },

  // Session Management
  { id: 'WSTG-SESS-01', name: 'Test Session Management Schema', category: 'Session Management' },
  { id: 'WSTG-SESS-02', name: 'Test Cookies Attributes', category: 'Session Management' },
  { id: 'WSTG-SESS-03', name: 'Test Session Fixation', category: 'Session Management' },
  { id: 'WSTG-SESS-04', name: 'Test Exposed Session Variables', category: 'Session Management' },
  { id: 'WSTG-SESS-05', name: 'Test Cross Site Request Forgery', category: 'Session Management' },
  { id: 'WSTG-SESS-06', name: 'Test Logout Functionality', category: 'Session Management' },
  { id: 'WSTG-SESS-07', name: 'Test Session Timeout', category: 'Session Management' },
  { id: 'WSTG-SESS-08', name: 'Test Session Puzzling', category: 'Session Management' },
  { id: 'WSTG-SESS-09', name: 'Test Session Hijacking', category: 'Session Management' },

  // Input Validation
  { id: 'WSTG-INPV-01', name: 'Test Reflected Cross Site Scripting', category: 'Input Validation' },
  { id: 'WSTG-INPV-02', name: 'Test Stored Cross Site Scripting', category: 'Input Validation' },
  { id: 'WSTG-INPV-03', name: 'Test HTTP Verb Tampering', category: 'Input Validation' },
  { id: 'WSTG-INPV-04', name: 'Test HTTP Parameter Pollution', category: 'Input Validation' },
  { id: 'WSTG-INPV-05', name: 'Test SQL Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-06', name: 'Test LDAP Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-07', name: 'Test XML Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-08', name: 'Test SSI Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-09', name: 'Test XPath Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-10', name: 'Test IMAP/SMTP Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-11', name: 'Test Code Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-12', name: 'Test Command Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-13', name: 'Test Format String Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-14', name: 'Test Incubated Vulnerability', category: 'Input Validation' },
  { id: 'WSTG-INPV-15', name: 'Test HTTP Splitting/Smuggling', category: 'Input Validation' },
  { id: 'WSTG-INPV-16', name: 'Test HTTP Incoming Requests', category: 'Input Validation' },
  { id: 'WSTG-INPV-17', name: 'Test Host Header Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-18', name: 'Test Server-Side Template Injection', category: 'Input Validation' },
  { id: 'WSTG-INPV-19', name: 'Test Server-Side Request Forgery', category: 'Input Validation' },

  // Error Handling
  { id: 'WSTG-ERRH-01', name: 'Test Improper Error Handling', category: 'Error Handling' },
  { id: 'WSTG-ERRH-02', name: 'Test Stack Traces', category: 'Error Handling' },

  // Cryptography
  { id: 'WSTG-CRYP-01', name: 'Test Weak Transport Layer Security', category: 'Cryptography' },
  { id: 'WSTG-CRYP-02', name: 'Test Padding Oracle', category: 'Cryptography' },
  { id: 'WSTG-CRYP-03', name: 'Test Sensitive Information via Unencrypted Channels', category: 'Cryptography' },
  { id: 'WSTG-CRYP-04', name: 'Test Weak Encryption', category: 'Cryptography' },

  // Business Logic
  { id: 'WSTG-BUSL-01', name: 'Test Business Logic Data Validation', category: 'Business Logic' },
  { id: 'WSTG-BUSL-02', name: 'Test Ability to Forge Requests', category: 'Business Logic' },
  { id: 'WSTG-BUSL-03', name: 'Test Integrity Checks', category: 'Business Logic' },
  { id: 'WSTG-BUSL-04', name: 'Test Process Timing', category: 'Business Logic' },
  { id: 'WSTG-BUSL-05', name: 'Test Number of Times Function Can Be Used', category: 'Business Logic' },
  { id: 'WSTG-BUSL-06', name: 'Test Circumvention of Work Flows', category: 'Business Logic' },
  { id: 'WSTG-BUSL-07', name: 'Test Defenses Against Application Misuse', category: 'Business Logic' },
  { id: 'WSTG-BUSL-08', name: 'Test Upload Unexpected File Types', category: 'Business Logic' },
  { id: 'WSTG-BUSL-09', name: 'Test Upload Malicious Files', category: 'Business Logic' },

  // Client-Side
  { id: 'WSTG-CLNT-01', name: 'Test DOM-Based Cross Site Scripting', category: 'Client-Side' },
  { id: 'WSTG-CLNT-02', name: 'Test JavaScript Execution', category: 'Client-Side' },
  { id: 'WSTG-CLNT-03', name: 'Test HTML Injection', category: 'Client-Side' },
  { id: 'WSTG-CLNT-04', name: 'Test Client-Side URL Redirect', category: 'Client-Side' },
  { id: 'WSTG-CLNT-05', name: 'Test CSS Injection', category: 'Client-Side' },
  { id: 'WSTG-CLNT-06', name: 'Test Client-Side Resource Manipulation', category: 'Client-Side' },
  { id: 'WSTG-CLNT-07', name: 'Test Cross Origin Resource Sharing', category: 'Client-Side' },
  { id: 'WSTG-CLNT-08', name: 'Test Cross Site Flashing', category: 'Client-Side' },
  { id: 'WSTG-CLNT-09', name: 'Test Clickjacking', category: 'Client-Side' },
  { id: 'WSTG-CLNT-10', name: 'Test WebSockets', category: 'Client-Side' },
  { id: 'WSTG-CLNT-11', name: 'Test Web Messaging', category: 'Client-Side' },
  { id: 'WSTG-CLNT-12', name: 'Test Browser Storage', category: 'Client-Side' },
  { id: 'WSTG-CLNT-13', name: 'Test Cross Site Script Inclusion', category: 'Client-Side' },

  // API Testing
  { id: 'WSTG-APIT-01', name: 'Test GraphQL', category: 'API Testing' },
];

export const WSTG_CATEGORIES = [...new Set(WSTG_TEST_CASES.map(tc => tc.category))];
