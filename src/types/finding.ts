import type { CVSSMetrics, Severity } from '@/lib/cvss4';

export interface EvidenceFile {
  file: File;
  preview: string;
  filename: string;
}

export interface FindingData {
  findingName: string;
  testCase: string;
  urlSystemIp: string;
  description: string;
  exploitationDetails: string;
  remediation: string;
  references: string[];
  cvssMetrics: CVSSMetrics;
  cvssVector: string;
  cvssScore: number;
  severity: Severity;
  firstOrgLink: string;
  evidenceFilename?: string;
}

export interface FindingFormData {
  findingName: string;
  testCase: string;
  urlSystemIp: string;
  description: string;
  exploitationDetails: string;
  remediation: string;
  references: string[];
  cvssMetrics: CVSSMetrics;
  evidence: EvidenceFile | null;
}
