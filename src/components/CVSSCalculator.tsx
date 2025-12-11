import { 
  CVSSMetrics, 
  CVSS_METRIC_OPTIONS, 
  METRIC_LABELS,
  buildCVSSVector,
  getFirstOrgLink,
  calculateCVSS4Score,
  getSeverity,
  getSeverityColor
} from '@/lib/cvss4';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink, Shield } from 'lucide-react';

interface CVSSCalculatorProps {
  metrics: CVSSMetrics;
  onChange: (metrics: CVSSMetrics) => void;
}

export function CVSSCalculator({ metrics, onChange }: CVSSCalculatorProps) {
  const vector = buildCVSSVector(metrics);
  const score = calculateCVSS4Score(metrics);
  const severity = getSeverity(score);
  const firstLink = getFirstOrgLink(vector);

  const handleMetricChange = (key: keyof CVSSMetrics, value: string) => {
    onChange({ ...metrics, [key]: value });
  };

  const exploitabilityMetrics: (keyof CVSSMetrics)[] = ['AV', 'AC', 'AT', 'PR', 'UI'];
  const impactMetrics: (keyof CVSSMetrics)[] = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Shield className="h-5 w-5" />
          CVSS v4.0 Calculator
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Score Display */}
        <div 
          className="flex items-center justify-between rounded-lg p-4 transition-colors"
          style={{ backgroundColor: `${getSeverityColor(severity)}20` }}
        >
          <div>
            <p className="text-sm text-muted-foreground">Base Score</p>
            <p 
              className="text-4xl font-bold"
              style={{ color: getSeverityColor(severity) }}
            >
              {score.toFixed(1)}
            </p>
            <p 
              className="text-sm font-medium uppercase tracking-wider"
              style={{ color: getSeverityColor(severity) }}
            >
              {severity}
            </p>
          </div>
          <a
            href={firstLink}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-muted-foreground hover:text-primary transition-colors"
          >
            <ExternalLink className="h-4 w-4" />
            FIRST Calculator
          </a>
        </div>

        {/* Vector String */}
        <div className="rounded-md bg-muted/50 p-3">
          <p className="text-xs text-muted-foreground mb-1">Vector String</p>
          <code className="text-xs font-mono text-foreground break-all">
            {vector}
          </code>
        </div>

        {/* Exploitability Metrics */}
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-3">
            Exploitability Metrics
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {exploitabilityMetrics.map((key) => (
              <div key={key} className="space-y-1.5">
                <Label className="text-xs">{METRIC_LABELS[key]}</Label>
                <Select
                  value={metrics[key]}
                  onValueChange={(value) => handleMetricChange(key, value)}
                >
                  <SelectTrigger className="h-9 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CVSS_METRIC_OPTIONS[key].map((option) => (
                      <SelectItem 
                        key={option.value} 
                        value={option.value}
                        className="text-xs"
                      >
                        {option.value}: {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>
        </div>

        {/* Impact Metrics */}
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-3">
            Impact Metrics
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {impactMetrics.map((key) => (
              <div key={key} className="space-y-1.5">
                <Label className="text-xs">{METRIC_LABELS[key]}</Label>
                <Select
                  value={metrics[key]}
                  onValueChange={(value) => handleMetricChange(key, value)}
                >
                  <SelectTrigger className="h-9 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CVSS_METRIC_OPTIONS[key].map((option) => (
                      <SelectItem 
                        key={option.value} 
                        value={option.value}
                        className="text-xs"
                      >
                        {option.value}: {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
