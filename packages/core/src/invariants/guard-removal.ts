import { SecurityInvariant, GuardDominatesParams } from '../types/invariant.js';
import { InvariantViolation, EvidencePathNode } from '../types/analysis.js';
import * as diff from 'diff';

export interface DiffInspectionInput {
  filePath: string;
  patchDiff: string;
  oldContent?: string;
  newContent?: string;
}

export function extractRemovedLines(patchDiff: string): { line: number; text: string }[] {
  const removed: { line: number; text: string }[] = [];
  try {
    const parsed = diff.parsePatch(patchDiff);
    for (const file of parsed) {
      for (const hunk of file.hunks) {
        let cur = hunk.oldStart;
        for (const line of hunk.lines) {
          if (line.startsWith('-') && !line.startsWith('---')) {
            removed.push({ line: cur, text: line.substring(1).trim() });
            cur++;
          } else if (!line.startsWith('+')) {
            cur++;
          }
        }
      }
    }
  } catch {
    // Resilient fallback for partial or loose diffs
    const lines = patchDiff.split(/\r?\n/);
    let lineIdx = 1;
    for (const raw of lines) {
      if (raw.startsWith('-') && !raw.startsWith('---')) {
        removed.push({ line: lineIdx, text: raw.substring(1).trim() });
      }
      lineIdx++;
    }
  }
  return removed;
}

export function checkGuardRemoval(
  diffInput: DiffInspectionInput,
  invariant: SecurityInvariant
): InvariantViolation | null {
  const params = invariant.params as GuardDominatesParams;
  const guardPattern = params.guard;

  const removedLines = extractRemovedLines(diffInput.patchDiff);
  const evidenceNodes: EvidencePathNode[] = [];

  for (const rem of removedLines) {
    if (rem.text.includes(guardPattern)) {
      evidenceNodes.push({
        file: diffInput.filePath,
        line: rem.line,
        codeSnippet: rem.text,
        role: 'REVERTED_LINE',
      });
    }
  }

  if (evidenceNodes.length === 0) {
    return null;
  }

  return {
    invariantId: invariant.id,
    advisoryId: invariant.advisoryId,
    verdict: 'PROVEN',
    summary: `Security invariant violated: Critical defensive guard '${guardPattern}' was removed in PR diff.`,
    evidencePath: evidenceNodes,
    details: {
      guard: guardPattern,
      removedLinesCount: evidenceNodes.length,
    },
    remediation: `Restore the defensive guard '${guardPattern}' protecting sink '${params.sink}'. Original fix was introduced in ${invariant.advisoryId}.`,
  };
}
