import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Trash2, List, AlertTriangle } from 'lucide-react';
import type { StoredFinding } from '@/types/finding';
import { getSeverityColor } from '@/lib/cvss4';

interface FindingsListProps {
  findings: StoredFinding[];
  onRemove: (id: string) => void;
}

export function FindingsList({ findings, onRemove }: FindingsListProps) {
  if (findings.length === 0) {
    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <List className="h-5 w-5" />
            Findings List
            <Badge variant="secondary" className="ml-auto">0</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <AlertTriangle className="h-8 w-8 mb-2 opacity-50" />
            <p className="text-sm">No findings added yet</p>
            <p className="text-xs">Fill out the form and click "Add Finding"</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-lg">
          <List className="h-5 w-5" />
          Findings List
          <Badge variant="secondary" className="ml-auto">{findings.length}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[300px]">
          <div className="space-y-2 p-4 pt-0">
            {findings.map((finding, index) => (
              <div
                key={finding.id}
                className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border/30"
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <span className="text-xs text-muted-foreground font-mono w-6">
                    #{index + 1}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm truncate">
                      {finding.data.findingName}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {finding.data.testCase} • {finding.data.urlSystemIp}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 ml-2">
                  <Badge
                    style={{ 
                      backgroundColor: getSeverityColor(finding.data.severity),
                      color: finding.data.severity === 'none' ? 'black' : 'white'
                    }}
                    className="text-xs font-mono"
                  >
                    {finding.data.cvssScore.toFixed(1)}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
                    onClick={() => onRemove(finding.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
