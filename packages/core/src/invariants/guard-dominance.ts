import { ParsedFile } from '../ast/parser.js';
import { ControlFlowAnalyzer } from '../ast/cfg.js';
import { SecurityInvariant, GuardDominatesParams } from '../types/invariant.js';
import { InvariantViolation, EvidencePathNode } from '../types/analysis.js';

export function checkGuardDominance(
  parsedFile: ParsedFile,
  invariant: SecurityInvariant
): InvariantViolation | null {
  const params = invariant.params as GuardDominatesParams;
  const cfg = new ControlFlowAnalyzer(parsedFile);

  const result = cfg.evaluateGuardDominance(params.sink, params.guard, params.source);

  if (result.dominated) {
    return null; // Invariant holds! No violation.
  }

  // Found violation:
  const violationTrace = result.violations[0];
  const evidenceNodes: EvidencePathNode[] = [];

  if (violationTrace) {
    evidenceNodes.push({
      file: violationTrace.sourceLocation.file,
      line: violationTrace.sourceLocation.line,
      codeSnippet: violationTrace.sourceLocation.snippet,
      role: 'SOURCE',
    });

    for (const step of violationTrace.callPath) {
      if (!step.isEntry && !step.isSink) {
        evidenceNodes.push({
          file: step.file,
          line: step.line,
          codeSnippet: step.snippet,
          role: 'CALL_SITE',
        });
      }
    }

    evidenceNodes.push({
      file: violationTrace.sinkLocation.file,
      line: violationTrace.sinkLocation.line,
      codeSnippet: violationTrace.sinkLocation.snippet,
      role: 'SINK',
    });

    evidenceNodes.push({
      file: parsedFile.filePath,
      line: violationTrace.sinkLocation.line,
      codeSnippet: `Missing required guard '${params.guard}' before reaching sink '${params.sink}'`,
      role: 'MISSING_GUARD',
    });
  }

  return {
    invariantId: invariant.id,
    advisoryId: invariant.advisoryId,
    verdict: 'PROVEN',
    summary: `Security invariant violated: Execution reaches sink '${params.sink}' without required guard '${params.guard}'`,
    evidencePath: evidenceNodes,
    details: {
      sink: params.sink,
      guard: params.guard,
      source: params.source,
      violationCount: result.violations.length,
      protectedSinksCount: result.protectedSinksCount,
    },
    remediation: `Ensure all paths reaching '${params.sink}' evaluate '${params.guard}' and reject unvalidated input. Refer to ${invariant.advisoryId}.`,
  };
}
