import { useState, useCallback } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { WSTG_TEST_CASES, WSTG_CATEGORIES } from '@/lib/wstg-testcases';
import { Plus, Trash2, FileText } from 'lucide-react';

interface FindingFormProps {
  findingName: string;
  setFindingName: (value: string) => void;
  testCase: string;
  setTestCase: (value: string) => void;
  urlSystemIp: string;
  setUrlSystemIp: (value: string) => void;
  description: string;
  setDescription: (value: string) => void;
  exploitationDetails: string;
  setExploitationDetails: (value: string) => void;
  remediation: string;
  setRemediation: (value: string) => void;
  references: string[];
  setReferences: (value: string[]) => void;
}

export function FindingForm({
  findingName,
  setFindingName,
  testCase,
  setTestCase,
  urlSystemIp,
  setUrlSystemIp,
  description,
  setDescription,
  exploitationDetails,
  setExploitationDetails,
  remediation,
  setRemediation,
  references,
  setReferences,
}: FindingFormProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>('');

  const filteredTestCases = selectedCategory && selectedCategory !== '_all'
    ? WSTG_TEST_CASES.filter(tc => tc.category === selectedCategory)
    : WSTG_TEST_CASES;

  const addReference = useCallback(() => {
    setReferences([...references, '']);
  }, [references, setReferences]);

  const removeReference = useCallback((index: number) => {
    setReferences(references.filter((_, i) => i !== index));
  }, [references, setReferences]);

  const updateReference = useCallback((index: number, value: string) => {
    const newRefs = [...references];
    newRefs[index] = value;
    setReferences(newRefs);
  }, [references, setReferences]);

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <FileText className="h-5 w-5" />
          Finding Details
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Finding Name */}
        <div className="space-y-1.5">
          <Label htmlFor="findingName">Finding Name *</Label>
          <Input
            id="findingName"
            value={findingName}
            onChange={(e) => setFindingName(e.target.value)}
            placeholder="e.g., Stored Cross-Site Scripting (XSS)"
            className="font-mono"
          />
        </div>

        {/* Test Case Selection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label>Category Filter</Label>
            <Select value={selectedCategory} onValueChange={setSelectedCategory}>
              <SelectTrigger>
                <SelectValue placeholder="All Categories" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_all">All Categories</SelectItem>
                {WSTG_CATEGORIES.map((cat) => (
                  <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="testCase">Test Case *</Label>
            <Select value={testCase} onValueChange={setTestCase}>
              <SelectTrigger>
                <SelectValue placeholder="Select test case" />
              </SelectTrigger>
              <SelectContent className="max-h-[300px]">
                {filteredTestCases.map((tc) => (
                  <SelectItem key={tc.id} value={tc.id}>
                    <span className="font-mono text-xs">{tc.id}</span>
                    <span className="text-muted-foreground ml-2">- {tc.name}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* URL/System/IP */}
        <div className="space-y-1.5">
          <Label htmlFor="urlSystemIp">URL / System / IP *</Label>
          <Input
            id="urlSystemIp"
            value={urlSystemIp}
            onChange={(e) => setUrlSystemIp(e.target.value)}
            placeholder="https://example.com/vulnerable-endpoint"
            className="font-mono"
          />
        </div>

        {/* Description */}
        <div className="space-y-1.5">
          <Label htmlFor="description">Description *</Label>
          <Textarea
            id="description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Detailed description of the vulnerability..."
            rows={4}
          />
        </div>

        {/* Exploitation Details */}
        <div className="space-y-1.5">
          <Label htmlFor="exploitationDetails">Exploitation Details *</Label>
          <Textarea
            id="exploitationDetails"
            value={exploitationDetails}
            onChange={(e) => setExploitationDetails(e.target.value)}
            placeholder="Steps to reproduce and exploit the vulnerability..."
            rows={4}
          />
        </div>

        {/* Recommended Remediation */}
        <div className="space-y-1.5">
          <Label htmlFor="remediation">Recommended Remediation *</Label>
          <Textarea
            id="remediation"
            value={remediation}
            onChange={(e) => setRemediation(e.target.value)}
            placeholder="Recommended steps to fix the vulnerability..."
            rows={4}
          />
        </div>

        {/* References */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>References</Label>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={addReference}
              className="h-8"
            >
              <Plus className="h-4 w-4 mr-1" />
              Add Reference
            </Button>
          </div>
          <div className="space-y-2">
            {references.map((ref, index) => (
              <div key={index} className="flex gap-2">
                <Input
                  value={ref}
                  onChange={(e) => updateReference(index, e.target.value)}
                  placeholder="https://owasp.org/..."
                  className="font-mono text-sm"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => removeReference(index)}
                  className="h-10 w-10 shrink-0 text-destructive hover:text-destructive"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
            {references.length === 0 && (
              <p className="text-sm text-muted-foreground italic">
                No references added. Click "Add Reference" to add one.
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
