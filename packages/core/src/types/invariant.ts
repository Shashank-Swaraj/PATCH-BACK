import { z } from 'zod';

export const InvariantTypeSchema = z.enum([
  'GUARD_DOMINATES',
  'GUARD_REMOVAL',
  'GUARD_BYPASS',
  'SANITIZER_SWAP',
  'INVERSE_PATCH',
]);

export type InvariantType = z.infer<typeof InvariantTypeSchema>;

/**
 * GUARD_DOMINATES invariant:
 * Whenever data from `source` reaches `sink`, execution MUST pass through `guard`.
 */
export const GuardDominatesParamsSchema = z.object({
  source: z.string().describe('Source identifier or pattern, e.g. req.query, req.params, input'),
  sink: z.string().describe('Dangerous sink function or method, e.g. res.sendFile, exec, eval, fs.readFile'),
  guard: z.string().describe('Required guard condition or function, e.g. startsWith, isValid, resolve'),
  guardConditionDescription: z.string().optional().describe('Human-readable description of what guard does'),
  targetFile: z.string().optional().describe('Target file where invariant was originally enforced'),
});

export type GuardDominatesParams = z.infer<typeof GuardDominatesParamsSchema>;

/**
 * SANITIZER_SWAP invariant:
 * Value passed to sink MUST be processed by required sanitizer function.
 */
export const SanitizerSwapParamsSchema = z.object({
  sink: z.string().describe('Dangerous sink function, e.g. exec, db.query, innerHTML'),
  requiredSanitizer: z.string().describe('Name of sanitizer function, e.g. escapeHtml, sanitizeInput'),
  targetArgumentIndex: z.number().default(0),
});

export type SanitizerSwapParams = z.infer<typeof SanitizerSwapParamsSchema>;

/**
 * INVERSE_PATCH invariant:
 * Catches accidental rollbacks or partial reverts of the original security patch.
 */
export const InversePatchParamsSchema = z.object({
  originalAddedLines: z.array(z.string()).describe('Critical lines added in original security fix'),
  originalRemovedLines: z.array(z.string()).describe('Vulnerable lines removed in original fix'),
  similarityThreshold: z.number().min(0).max(1).default(0.7),
});

export type InversePatchParams = z.infer<typeof InversePatchParamsSchema>;

/**
 * Comprehensive Invariant Definition stored in Patch Memory
 */
export const SecurityInvariantSchema = z.object({
  id: z.string().describe('Unique identifier for invariant, e.g. INV-GHSA-2022-001-01'),
  advisoryId: z.string().describe('Associated CVE or GHSA identifier'),
  packageName: z.string().describe('Affected package name'),
  createdAt: z.string().datetime().default(() => new Date().toISOString()),
  type: InvariantTypeSchema,
  params: z.union([
    GuardDominatesParamsSchema,
    SanitizerSwapParamsSchema,
    InversePatchParamsSchema,
  ]),
  vulnerabilityType: z.string().describe('CWE category, e.g. CWE-22 Path Traversal, CWE-78 Command Injection'),
  fixCommitSha: z.string().describe('Commit SHA where fix was introduced'),
  rationale: z.string().describe('Explanation of why this fix is critical to prevent regression'),
  enabled: z.boolean().default(true),
});

export type SecurityInvariant = z.infer<typeof SecurityInvariantSchema>;
