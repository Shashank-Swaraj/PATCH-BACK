import { z } from 'zod';
import { SecurityInvariant } from './invariant.js';

export const VerdictTierSchema = z.enum([
  'PROVEN',  // Deterministic violation proven by AST/reachability graph or direct deletion
  'LIKELY',  // Strong heuristic match (e.g. inverse patch similarity without proven flow)
  'REVIEW',  // Complex dynamic pattern; abstains from false alarms, flags for maintainer review
  'BENIGN',  // No regression detected, invariant remains fully satisfied
]);

export type VerdictTier = z.infer<typeof VerdictTierSchema>;

export const EvidencePathNodeSchema = z.object({
  file: z.string(),
  line: z.number(),
  column: z.number().optional(),
  codeSnippet: z.string(),
  role: z.enum(['SOURCE', 'CALL_SITE', 'SINK', 'MISSING_GUARD', 'MODIFIED_GUARD', 'REVERTED_LINE']),
});

export type EvidencePathNode = z.infer<typeof EvidencePathNodeSchema>;

export const InvariantViolationSchema = z.object({
  invariantId: z.string(),
  advisoryId: z.string(),
  verdict: VerdictTierSchema,
  summary: z.string(),
  evidencePath: z.array(EvidencePathNodeSchema),
  details: z.record(z.unknown()).optional(),
  remediation: z.string(),
});

export type InvariantViolation = z.infer<typeof InvariantViolationSchema>;

export const PRCheckResultSchema = z.object({
  prNumber: z.number().optional(),
  commitSha: z.string().optional(),
  totalInvariantsChecked: z.number(),
  passedInvariantsCount: z.number(),
  violations: z.array(InvariantViolationSchema),
  overallVerdict: VerdictTierSchema,
  durationMs: z.number(),
  timestamp: z.string().datetime().default(() => new Date().toISOString()),
});

export type PRCheckResult = z.infer<typeof PRCheckResultSchema>;
