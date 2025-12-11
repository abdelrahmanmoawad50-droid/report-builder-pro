import { useState, useCallback } from 'react';
import { CVSSCalculator } from '@/components/CVSSCalculator';
import { FindingForm } from '@/components/FindingForm';
import { EvidenceUpload } from '@/components/EvidenceUpload';
import { ActionButtons } from '@/components/ActionButtons';
import { FindingsList } from '@/components/FindingsList';
import { DEFAULT_METRICS, type CVSSMetrics, buildCVSSVector, calculateCVSS4Score, getFirstOrgLink, getSeverity } from '@/lib/cvss4';
import type { EvidenceFile, FindingFormData, StoredFinding, FindingData } from '@/types/finding';
import { Shield } from 'lucide-react';

const Index = () => {
  const [findingName, setFindingName] = useState('');
  const [testCase, setTestCase] = useState('WSTG-INPV-02');
  const [urlSystemIp, setUrlSystemIp] = useState('');
  const [description, setDescription] = useState('');
  const [exploitationDetails, setExploitationDetails] = useState('');
  const [remediation, setRemediation] = useState('');
  const [references, setReferences] = useState<string[]>([]);
  const [cvssMetrics, setCvssMetrics] = useState<CVSSMetrics>(DEFAULT_METRICS);
  const [evidence, setEvidence] = useState<EvidenceFile | null>(null);
  
  // Multi-finding state
  const [findings, setFindings] = useState<StoredFinding[]>([]);

  const clearForm = useCallback(() => {
    setFindingName('');
    setTestCase('WSTG-INPV-02');
    setUrlSystemIp('');
    setDescription('');
    setExploitationDetails('');
    setRemediation('');
    setReferences([]);
    setCvssMetrics(DEFAULT_METRICS);
    setEvidence(null);
  }, []);

  const handleClear = useCallback(() => {
    clearForm();
    setFindings([]);
  }, [clearForm]);

  const handleImport = useCallback((data: FindingFormData) => {
    setFindingName(data.findingName);
    setTestCase(data.testCase);
    setUrlSystemIp(data.urlSystemIp);
    setDescription(data.description);
    setExploitationDetails(data.exploitationDetails);
    setRemediation(data.remediation);
    setReferences(data.references);
    if (data.cvssMetrics) {
      setCvssMetrics({ ...DEFAULT_METRICS, ...data.cvssMetrics });
    }
  }, []);

  const handleAddFinding = useCallback(() => {
    const vector = buildCVSSVector(cvssMetrics);
    const score = calculateCVSS4Score(cvssMetrics);
    const severity = getSeverity(score);

    const findingData: FindingData = {
      findingName,
      testCase,
      urlSystemIp,
      description,
      exploitationDetails,
      remediation,
      references,
      cvssMetrics,
      cvssVector: vector,
      cvssScore: score,
      severity,
      firstOrgLink: getFirstOrgLink(vector),
      evidenceFilename: evidence?.filename,
    };

    const storedFinding: StoredFinding = {
      id: crypto.randomUUID(),
      data: findingData,
      evidencePreview: evidence?.preview,
    };

    setFindings(prev => [...prev, storedFinding]);
    clearForm();
  }, [findingName, testCase, urlSystemIp, description, exploitationDetails, remediation, references, cvssMetrics, evidence, clearForm]);

  const handleRemoveFinding = useCallback((id: string) => {
    setFindings(prev => prev.filter(f => f.id !== id));
  }, []);

  const formData = {
    findingName,
    testCase,
    urlSystemIp,
    description,
    exploitationDetails,
    remediation,
    references,
    cvssMetrics,
    evidence,
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="container max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-primary/10">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">
                Vulnerability Documentation Tool
              </h1>
              <p className="text-sm text-muted-foreground">
                CVSS v4.0 Calculator & LaTeX Report Generator
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Actions at top for quick access */}
        <ActionButtons 
          formData={formData}
          findings={findings}
          onClear={handleClear}
          onImport={handleImport}
          onAddFinding={handleAddFinding}
        />

        {/* Findings List */}
        <FindingsList 
          findings={findings}
          onRemove={handleRemoveFinding}
        />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column */}
          <div className="space-y-6">
            <FindingForm
              findingName={findingName}
              setFindingName={setFindingName}
              testCase={testCase}
              setTestCase={setTestCase}
              urlSystemIp={urlSystemIp}
              setUrlSystemIp={setUrlSystemIp}
              description={description}
              setDescription={setDescription}
              exploitationDetails={exploitationDetails}
              setExploitationDetails={setExploitationDetails}
              remediation={remediation}
              setRemediation={setRemediation}
              references={references}
              setReferences={setReferences}
            />
          </div>

          {/* Right Column */}
          <div className="space-y-6">
            <CVSSCalculator
              metrics={cvssMetrics}
              onChange={setCvssMetrics}
            />
            <EvidenceUpload
              evidence={evidence}
              setEvidence={setEvidence}
            />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/50 mt-12">
        <div className="container max-w-7xl mx-auto px-4 py-4">
          <p className="text-sm text-muted-foreground text-center">
            Penetration Testing Vulnerability Documentation Tool • CVSS v4.0 Compliant
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
