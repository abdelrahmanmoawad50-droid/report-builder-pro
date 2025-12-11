import { useCallback, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { ImageIcon, Upload, X } from 'lucide-react';
import type { EvidenceFile } from '@/types/finding';

interface EvidenceUploadProps {
  evidence: EvidenceFile | null;
  setEvidence: (evidence: EvidenceFile | null) => void;
}

export function EvidenceUpload({ evidence, setEvidence }: EvidenceUploadProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleFileSelect = useCallback((file: File) => {
    if (!file.type.startsWith('image/')) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const preview = e.target?.result as string;
      const filename = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
      setEvidence({ file, preview, filename });
    };
    reader.readAsDataURL(file);
  }, [setEvidence]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  }, [handleFileSelect]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFileSelect(file);
  }, [handleFileSelect]);

  const clearEvidence = useCallback(() => {
    setEvidence(null);
  }, [setEvidence]);

  const updateFilename = useCallback((filename: string) => {
    if (evidence) {
      setEvidence({ ...evidence, filename: filename.replace(/[^a-zA-Z0-9.-]/g, '_') });
    }
  }, [evidence, setEvidence]);

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <ImageIcon className="h-5 w-5" />
          Evidence Screenshot
        </CardTitle>
      </CardHeader>
      <CardContent>
        {evidence ? (
          <div className="space-y-4">
            <div className="relative rounded-lg border border-border overflow-hidden bg-muted/20">
              <img
                src={evidence.preview}
                alt="Evidence preview"
                className="w-full max-h-[300px] object-contain"
              />
              <Button
                variant="destructive"
                size="icon"
                className="absolute top-2 right-2 h-8 w-8"
                onClick={clearEvidence}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="evidenceFilename">Filename</Label>
              <Input
                id="evidenceFilename"
                value={evidence.filename}
                onChange={(e) => updateFilename(e.target.value)}
                placeholder="evidence.png"
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                This filename will be used in the LaTeX output
              </p>
            </div>
          </div>
        ) : (
          <div
            className={`
              relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed 
              p-8 transition-colors cursor-pointer
              ${isDragging 
                ? 'border-primary bg-primary/5' 
                : 'border-border hover:border-primary/50 hover:bg-muted/20'
              }
            `}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => document.getElementById('evidence-input')?.click()}
          >
            <Upload className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium">
              Drop image here or click to upload
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              PNG, JPG, GIF up to 10MB
            </p>
            <input
              id="evidence-input"
              type="file"
              accept="image/*"
              onChange={handleInputChange}
              className="sr-only"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
