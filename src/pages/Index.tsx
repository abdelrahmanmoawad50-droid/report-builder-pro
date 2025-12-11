import { useState, useCallback } from 'react';
import { CVSSCalculator } from '@/components/CVSSCalculator';
import { FindingForm } from '@/components/FindingForm';
import { EvidenceUpload } from '@/components/EvidenceUpload';
import { ActionButtons } from '@/components/ActionButtons';
import { DEFAULT_METRICS, type CVSSMetrics } from '@/lib/cvss4';
import type { EvidenceFile, FindingFormData } from '@/types/finding';
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

  const handleClear = useCallback(() => {
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
          onClear={handleClear}
          onImport={handleImport}
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
