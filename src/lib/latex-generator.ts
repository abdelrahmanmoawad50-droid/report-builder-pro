import type { FindingData } from '@/types/finding';
import { getSeverity } from './cvss4';

// Escape special LaTeX characters
function escapeLatex(text: string): string {
  return text
    .replace(/\\/g, '\\textbackslash{}')
    .replace(/&/g, '\\&')
    .replace(/%/g, '\\%')
    .replace(/\$/g, '\\$')
    .replace(/#/g, '\\#')
    .replace(/_/g, '\\_')
    .replace(/\{/g, '\\{')
    .replace(/\}/g, '\\}')
    .replace(/~/g, '\\textasciitilde{}')
    .replace(/\^/g, '\\textasciicircum{}');
}

// Don't escape URLs - they need special handling
function formatUrl(url: string): string {
  return url;
}

export function generateLatex(finding: FindingData): string {
  const severity = getSeverity(finding.cvssScore);
  const evidencePath = `images/findings/${severity}/${finding.evidenceFilename || 'evidence.png'}`;
  
  const referencesItems = finding.references
    .filter(ref => ref.trim())
    .map(ref => `        \\item \\url{${formatUrl(ref)}}`)
    .join('\n');

  const latex = `\\subsubsection{${escapeLatex(finding.findingName)}} 
\\label{sec:creds}
\\noindent
\\vulntext{${finding.cvssScore.toFixed(1)}} 
\\color{black}{}
\\noindent

\\textbf{CVSS v4.0 Vector:} 

\\href{${finding.firstOrgLink}}{${finding.cvssVector}}

\\textbf{Test Case:} ${escapeLatex(finding.testCase)}

\\noindent
\\textbf{URL/Systems/IP}:

\\url{${formatUrl(finding.urlSystemIp)}}

\\textbf{Description}:
    \\newline ${escapeLatex(finding.description)}

\\noindent
\\textbf{Exploitation Details}:
    \\newline ${escapeLatex(finding.exploitationDetails)}
\\noindent

\\textbf{Evidence}:

The following Screenshot highlights the impact of the finding:

\\Figure[placement=h, width=\\textwidth, frame]{${evidencePath}}

\\newpage

\\noindent
\\textbf{Recommended Remediation}:
    \\newline ${escapeLatex(finding.remediation)}
\\noindent

\\textbf{References}:
    \\begin{itemize}
${referencesItems}
    \\end{itemize}

\\newpage
`;

  return latex;
}
