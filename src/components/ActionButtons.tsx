import JSZip from 'jszip';
import { saveAs } from 'file-saver';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Download, 
  Upload, 
  FileDown, 
  Trash2, 
  Eye,
  Settings
} from 'lucide-react';
import { generateLatex } from '@/lib/latex-generator';
import { 
  buildCVSSVector, 
  calculateCVSS4Score, 
  getFirstOrgLink, 
  getSeverity 
} from '@/lib/cvss4';
import type { FindingFormData, FindingData, EvidenceFile } from '@/types/finding';
import type { CVSSMetrics } from '@/lib/cvss4';
import { useToast } from '@/hooks/use-toast';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useState } from 'react';

interface ActionButtonsProps {
  formData: {
    findingName: string;
    testCase: string;
    urlSystemIp: string;
    description: string;
    exploitationDetails: string;
    remediation: string;
    references: string[];
    cvssMetrics: CVSSMetrics;
    evidence: EvidenceFile | null;
  };
  onClear: () => void;
  onImport: (data: FindingFormData) => void;
}

export function ActionButtons({ formData, onClear, onImport }: ActionButtonsProps) {
  const { toast } = useToast();
  const [previewContent, setPreviewContent] = useState<string>('');
  const [previewOpen, setPreviewOpen] = useState(false);

  const validateForm = (): boolean => {
    if (!formData.findingName.trim()) {
      toast({ title: 'Missing Finding Name', variant: 'destructive' });
      return false;
    }
    if (!formData.testCase) {
      toast({ title: 'Missing Test Case', variant: 'destructive' });
      return false;
    }
    if (!formData.urlSystemIp.trim()) {
      toast({ title: 'Missing URL/System/IP', variant: 'destructive' });
      return false;
    }
    if (!formData.description.trim()) {
      toast({ title: 'Missing Description', variant: 'destructive' });
      return false;
    }
    if (!formData.exploitationDetails.trim()) {
      toast({ title: 'Missing Exploitation Details', variant: 'destructive' });
      return false;
    }
    if (!formData.remediation.trim()) {
      toast({ title: 'Missing Remediation', variant: 'destructive' });
      return false;
    }
    return true;
  };

  const buildFindingData = (): FindingData => {
    const vector = buildCVSSVector(formData.cvssMetrics);
    const score = calculateCVSS4Score(formData.cvssMetrics);
    const severity = getSeverity(score);
    
    return {
      findingName: formData.findingName,
      testCase: formData.testCase,
      urlSystemIp: formData.urlSystemIp,
      description: formData.description,
      exploitationDetails: formData.exploitationDetails,
      remediation: formData.remediation,
      references: formData.references,
      cvssMetrics: formData.cvssMetrics,
      cvssVector: vector,
      cvssScore: score,
      severity,
      firstOrgLink: getFirstOrgLink(vector),
      evidenceFilename: formData.evidence?.filename,
    };
  };

  const handlePreview = () => {
    if (!validateForm()) return;
    const findingData = buildFindingData();
    const latex = generateLatex(findingData);
    setPreviewContent(latex);
    setPreviewOpen(true);
  };

  const handleGenerateZip = async () => {
    if (!validateForm()) return;

    const findingData = buildFindingData();
    const latex = generateLatex(findingData);
    const severity = findingData.severity;

    const zip = new JSZip();
    
    // Add LaTeX file
    zip.file('output/finding.tex', latex);
    
    // Add evidence image if exists
    if (formData.evidence) {
      const imageFolder = `output/images/findings/${severity}/`;
      
      // Convert base64 to blob
      const base64Data = formData.evidence.preview.split(',')[1];
      const binaryString = atob(base64Data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      
      zip.file(imageFolder + formData.evidence.filename, bytes);
    }

    const content = await zip.generateAsync({ type: 'blob' });
    const filename = `finding_${formData.findingName.replace(/[^a-zA-Z0-9]/g, '_')}.zip`;
    saveAs(content, filename);

    toast({
      title: 'ZIP Generated',
      description: `Downloaded ${filename}`,
    });
  };

  const handleExportJson = () => {
    const exportData = {
      findingName: formData.findingName,
      testCase: formData.testCase,
      urlSystemIp: formData.urlSystemIp,
      description: formData.description,
      exploitationDetails: formData.exploitationDetails,
      remediation: formData.remediation,
      references: formData.references,
      cvssMetrics: formData.cvssMetrics,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const filename = `finding_${formData.findingName.replace(/[^a-zA-Z0-9]/g, '_') || 'export'}.json`;
    saveAs(blob, filename);

    toast({
      title: 'JSON Exported',
      description: `Downloaded ${filename}`,
    });
  };

  const handleImportJson = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const data = JSON.parse(event.target?.result as string);
          onImport({
            findingName: data.findingName || '',
            testCase: data.testCase || 'WSTG-INPV-02',
            urlSystemIp: data.urlSystemIp || '',
            description: data.description || '',
            exploitationDetails: data.exploitationDetails || '',
            remediation: data.remediation || '',
            references: data.references || [],
            cvssMetrics: data.cvssMetrics || {},
            evidence: null,
          });
          toast({
            title: 'JSON Imported',
            description: 'Finding data loaded successfully',
          });
        } catch {
          toast({
            title: 'Import Failed',
            description: 'Invalid JSON file',
            variant: 'destructive',
          });
        }
      };
      reader.readAsText(file);
    };
    input.click();
  };

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Settings className="h-5 w-5" />
          Actions
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" onClick={handlePreview} className="w-full">
                <Eye className="h-4 w-4 mr-2" />
                Preview
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[80vh]">
              <DialogHeader>
                <DialogTitle>LaTeX Preview</DialogTitle>
              </DialogHeader>
              <ScrollArea className="h-[60vh]">
                <pre className="text-xs font-mono bg-muted p-4 rounded-lg whitespace-pre-wrap">
                  {previewContent}
                </pre>
              </ScrollArea>
            </DialogContent>
          </Dialog>

          <Button onClick={handleGenerateZip} className="w-full">
            <Download className="h-4 w-4 mr-2" />
            Generate ZIP
          </Button>

          <Button variant="outline" onClick={handleExportJson} className="w-full">
            <FileDown className="h-4 w-4 mr-2" />
            Export JSON
          </Button>

          <Button variant="outline" onClick={handleImportJson} className="w-full">
            <Upload className="h-4 w-4 mr-2" />
            Import JSON
          </Button>

          <Button variant="destructive" onClick={onClear} className="w-full">
            <Trash2 className="h-4 w-4 mr-2" />
            Clear Form
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
