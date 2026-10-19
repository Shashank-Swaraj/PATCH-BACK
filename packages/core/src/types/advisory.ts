import { z } from 'zod';

export const AdvisoryRecordSchema = z.object({
  id: z.string().describe('Advisory ID e.g. GHSA-xxxx-yyyy or CVE-2024-xxxx'),
  title: z.string(),
  description: z.string(),
  cwe: z.string().describe('e.g. CWE-22, CWE-78, CWE-1321'),
  severity: z.enum(['LOW', 'MODERATE', 'HIGH', 'CRITICAL']),
  affectedPackage: z.string(),
  affectedVersions: z.string(),
  patchedVersions: z.string(),
  fixCommitSha: z.string(),
  fixCommitUrl: z.string().url().optional(),
  patchDiff: z.string().describe('Unified diff of the patch commit'),
  discoveredAt: z.string(),
});

export type AdvisoryRecord = z.infer<typeof AdvisoryRecordSchema>;
