// CVSS v4.0 Implementation
// Based on FIRST.org CVSS v4.0 specification

export interface CVSSMetrics {
  AV: 'N' | 'A' | 'L' | 'P';  // Attack Vector
  AC: 'L' | 'H';              // Attack Complexity
  AT: 'N' | 'P';              // Attack Requirements
  PR: 'N' | 'L' | 'H';        // Privileges Required
  UI: 'N' | 'P' | 'A';        // User Interaction
  VC: 'H' | 'L' | 'N';        // Vulnerable System Confidentiality
  VI: 'H' | 'L' | 'N';        // Vulnerable System Integrity
  VA: 'H' | 'L' | 'N';        // Vulnerable System Availability
  SC: 'H' | 'L' | 'N';        // Subsequent System Confidentiality
  SI: 'H' | 'L' | 'N';        // Subsequent System Integrity
  SA: 'H' | 'L' | 'N';        // Subsequent System Availability
}

export const CVSS_METRIC_OPTIONS = {
  AV: [
    { value: 'N', label: 'Network', description: 'Remotely exploitable' },
    { value: 'A', label: 'Adjacent', description: 'Adjacent network access required' },
    { value: 'L', label: 'Local', description: 'Local access required' },
    { value: 'P', label: 'Physical', description: 'Physical access required' },
  ],
  AC: [
    { value: 'L', label: 'Low', description: 'No specialized conditions' },
    { value: 'H', label: 'High', description: 'Specialized conditions required' },
  ],
  AT: [
    { value: 'N', label: 'None', description: 'No specific deployment requirements' },
    { value: 'P', label: 'Present', description: 'Specific deployment/config required' },
  ],
  PR: [
    { value: 'N', label: 'None', description: 'No privileges required' },
    { value: 'L', label: 'Low', description: 'Low privileges required' },
    { value: 'H', label: 'High', description: 'High privileges required' },
  ],
  UI: [
    { value: 'N', label: 'None', description: 'No user interaction' },
    { value: 'P', label: 'Passive', description: 'Passive user interaction' },
    { value: 'A', label: 'Active', description: 'Active user interaction' },
  ],
  VC: [
    { value: 'H', label: 'High', description: 'Total confidentiality loss' },
    { value: 'L', label: 'Low', description: 'Some confidentiality loss' },
    { value: 'N', label: 'None', description: 'No confidentiality impact' },
  ],
  VI: [
    { value: 'H', label: 'High', description: 'Total integrity loss' },
    { value: 'L', label: 'Low', description: 'Some integrity loss' },
    { value: 'N', label: 'None', description: 'No integrity impact' },
  ],
  VA: [
    { value: 'H', label: 'High', description: 'Total availability loss' },
    { value: 'L', label: 'Low', description: 'Some availability loss' },
    { value: 'N', label: 'None', description: 'No availability impact' },
  ],
  SC: [
    { value: 'H', label: 'High', description: 'Total subsequent confidentiality loss' },
    { value: 'L', label: 'Low', description: 'Some subsequent confidentiality loss' },
    { value: 'N', label: 'None', description: 'No subsequent confidentiality impact' },
  ],
  SI: [
    { value: 'H', label: 'High', description: 'Total subsequent integrity loss' },
    { value: 'L', label: 'Low', description: 'Some subsequent integrity loss' },
    { value: 'N', label: 'None', description: 'No subsequent integrity impact' },
  ],
  SA: [
    { value: 'H', label: 'High', description: 'Total subsequent availability loss' },
    { value: 'L', label: 'Low', description: 'Some subsequent availability loss' },
    { value: 'N', label: 'None', description: 'No subsequent availability impact' },
  ],
};

export const METRIC_LABELS: Record<keyof CVSSMetrics, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  AT: 'Attack Requirements',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  VC: 'Vuln. Confidentiality',
  VI: 'Vuln. Integrity',
  VA: 'Vuln. Availability',
  SC: 'Subseq. Confidentiality',
  SI: 'Subseq. Integrity',
  SA: 'Subseq. Availability',
};

export function buildCVSSVector(metrics: CVSSMetrics): string {
  return `CVSS:4.0/AV:${metrics.AV}/AC:${metrics.AC}/AT:${metrics.AT}/PR:${metrics.PR}/UI:${metrics.UI}/VC:${metrics.VC}/VI:${metrics.VI}/VA:${metrics.VA}/SC:${metrics.SC}/SI:${metrics.SI}/SA:${metrics.SA}`;
}

export function getFirstOrgLink(vector: string): string {
  return `https://www.first.org/cvss/calculator/4-0#${vector}`;
}

// CVSS 4.0 Scoring Algorithm Implementation
// This is a simplified implementation based on the CVSS 4.0 specification

const EQ_LOOKUP: Record<string, Record<string, number>> = {
  eq1: { '0': 1, '1': 4, '2': 5 },
  eq2: { '0': 1, '1': 2 },
  eq3: { '0': 7, '1': 6, '2': 5 },
  eq4: { '0': 6, '1': 5, '2': 4 },
  eq5: { '0': 1, '1': 1, '2': 1 },
  eq6: { '0': 1, '1': 1 },
};

function getEQ1(metrics: CVSSMetrics): string {
  if (metrics.AV === 'N' && metrics.PR === 'N' && metrics.UI === 'N') return '0';
  if ((metrics.AV === 'N' || metrics.PR === 'N' || metrics.UI === 'N') && 
      !(metrics.AV === 'N' && metrics.PR === 'N' && metrics.UI === 'N') &&
      !(metrics.AV === 'P' || (metrics.PR === 'H' && metrics.UI !== 'N'))) return '1';
  return '2';
}

function getEQ2(metrics: CVSSMetrics): string {
  if (metrics.AC === 'L' && metrics.AT === 'N') return '0';
  return '1';
}

function getEQ3(metrics: CVSSMetrics): string {
  if (metrics.VC === 'H' && metrics.VI === 'H') return '0';
  if (!(metrics.VC === 'H' && metrics.VI === 'H') && (metrics.VC === 'H' || metrics.VI === 'H' || metrics.VA === 'H')) return '1';
  return '2';
}

function getEQ4(metrics: CVSSMetrics): string {
  if (metrics.SC === 'H' && metrics.SI === 'H') return '0';
  if (!(metrics.SC === 'H' && metrics.SI === 'H') && (metrics.SC === 'H' || metrics.SI === 'H' || metrics.SA === 'H')) return '1';
  return '2';
}

// MacroVector to score mapping (simplified version)
const MACRO_VECTOR_SCORES: Record<string, number> = {
  '000000': 10.0, '000001': 9.9, '000010': 9.8, '000011': 9.5,
  '000100': 10.0, '000101': 9.6, '000110': 9.3, '000111': 8.7,
  '001000': 9.9, '001001': 9.7, '001010': 9.5, '001011': 9.2,
  '001100': 9.6, '001101': 9.1, '001110': 8.8, '001111': 8.4,
  '010000': 9.3, '010001': 9.0, '010010': 8.9, '010011': 8.5,
  '010100': 9.0, '010101': 8.7, '010110': 8.4, '010111': 8.0,
  '011000': 8.9, '011001': 8.6, '011010': 8.3, '011011': 7.9,
  '011100': 8.6, '011101': 8.2, '011110': 7.8, '011111': 7.4,
  '100000': 8.8, '100001': 8.5, '100010': 8.2, '100011': 7.9,
  '100100': 8.5, '100101': 8.1, '100110': 7.8, '100111': 7.4,
  '101000': 8.3, '101001': 7.9, '101010': 7.6, '101011': 7.2,
  '101100': 8.0, '101101': 7.5, '101110': 7.2, '101111': 6.8,
  '110000': 7.9, '110001': 7.5, '110010': 7.2, '110011': 6.8,
  '110100': 7.6, '110101': 7.1, '110110': 6.8, '110111': 6.4,
  '111000': 7.4, '111001': 6.9, '111010': 6.6, '111011': 6.2,
  '111100': 7.1, '111101': 6.5, '111110': 6.2, '111111': 5.8,
  '200000': 6.8, '200001': 6.4, '200010': 6.1, '200011': 5.7,
  '200100': 6.5, '200101': 6.0, '200110': 5.7, '200111': 5.3,
  '201000': 6.3, '201001': 5.8, '201010': 5.5, '201011': 5.1,
  '201100': 6.0, '201101': 5.4, '201110': 5.1, '201111': 4.7,
  '210000': 5.9, '210001': 5.4, '210010': 5.1, '210011': 4.7,
  '210100': 5.6, '210101': 5.0, '210110': 4.7, '210111': 4.3,
  '211000': 5.4, '211001': 4.8, '211010': 4.5, '211011': 4.1,
  '211100': 5.1, '211101': 4.4, '211110': 4.1, '211111': 3.7,
  '220000': 5.0, '220001': 4.4, '220010': 4.1, '220011': 3.7,
  '220100': 4.7, '220101': 4.0, '220110': 3.7, '220111': 3.3,
  '221000': 4.5, '221001': 3.8, '221010': 3.5, '221011': 3.1,
  '221100': 4.2, '221101': 3.4, '221110': 3.1, '221111': 2.7,
};

export function calculateCVSS4Score(metrics: CVSSMetrics): number {
  // Check if all impact metrics are None
  if (metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' &&
      metrics.SC === 'N' && metrics.SI === 'N' && metrics.SA === 'N') {
    return 0.0;
  }

  const eq1 = getEQ1(metrics);
  const eq2 = getEQ2(metrics);
  const eq3 = getEQ3(metrics);
  const eq4 = getEQ4(metrics);
  const eq5 = '0'; // Simplified - not using threat metrics
  const eq6 = '0'; // Simplified - not using supplemental metrics

  const macroVector = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  
  return MACRO_VECTOR_SCORES[macroVector] ?? 5.0;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export function getSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}

export function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'hsl(var(--severity-critical))';
    case 'high': return 'hsl(var(--severity-high))';
    case 'medium': return 'hsl(var(--severity-medium))';
    case 'low': return 'hsl(var(--severity-low))';
    default: return 'hsl(var(--severity-none))';
  }
}

export const DEFAULT_METRICS: CVSSMetrics = {
  AV: 'N',
  AC: 'L',
  AT: 'N',
  PR: 'N',
  UI: 'N',
  VC: 'H',
  VI: 'H',
  VA: 'H',
  SC: 'N',
  SI: 'N',
  SA: 'N',
};
