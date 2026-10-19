import * as diff from 'diff';
import { SecurityInvariant, InversePatchParams } from '../types/invariant.js';
import { InvariantViolation, EvidencePathNode } from '../types/analysis.js';

function normalizeLine(line: string): string {
  return line.trim().replace(/\s+/g, ' ').replace(/[;,\(\)\{\}]/g, '');
}

export function extractDiffLines(patchDiff: string): {
  deleted: { lineNum: number; content: string; normalized: string }[];
  added: { lineNum: number; content: string; normalized: string }[];
} {
  const deleted: { lineNum: number; content: string; normalized: string }[] = [];
  const added: { lineNum: number; content: string; normalized: string }[] = [];

  try {
    const parsedDiff = diff.parsePatch(patchDiff);
    for (const file of parsedDiff) {
      for (const hunk of file.hunks) {
        let currentOldLine = hunk.oldStart;
        let currentNewLine = hunk.newStart;

        for (const rawLine of hunk.lines) {
          if (rawLine.startsWith('-') && !rawLine.startsWith('---')) {
            const content = rawLine.substring(1).trim();
            if (content.length > 3) {
              deleted.push({
                lineNum: currentOldLine,
                content,
                normalized: normalizeLine(content),
              });
            }
            currentOldLine++;
          } else if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
            const content = rawLine.substring(1).trim();
            if (content.length > 3) {
              added.push({
                lineNum: currentNewLine,
                content,
                normalized: normalizeLine(content),
              });
            }
            currentNewLine++;
          } else {
            currentOldLine++;
            currentNewLine++;
          }
        }
      }
    }
  } catch {
    // Resilient fallback for partial or loose diff strings
    const lines = patchDiff.split(/\r?\n/);
    let lineIdx = 1;
    for (const raw of lines) {
      if (raw.startsWith('-') && !raw.startsWith('---')) {
        const content = raw.substring(1).trim();
        if (content.length > 3) {
          deleted.push({ lineNum: lineIdx, content, normalized: normalizeLine(content) });
        }
      } else if (raw.startsWith('+') && !raw.startsWith('+++')) {
        const content = raw.substring(1).trim();
        if (content.length > 3) {
          added.push({ lineNum: lineIdx, content, normalized: normalizeLine(content) });
        }
      }
      lineIdx++;
    }
  }

  return { deleted, added };
}

export function checkInversePatch(
  patchDiff: string,
  invariant: SecurityInvariant,
  filePath: string = 'unknown.js'
): InvariantViolation | null {
  const params = invariant.params as InversePatchParams;
  const { deleted: prDeletedLines, added: prAddedLines } = extractDiffLines(patchDiff);

  // Check 1: Did PR delete lines that the original fix added?
  const originalAddedNormalized = new Set(
    params.originalAddedLines.map(normalizeLine).filter((l) => l.length > 3)
  );

  const matchedDeletions: EvidencePathNode[] = [];
  for (const del of prDeletedLines) {
    for (const orig of originalAddedNormalized) {
      if (del.normalized.includes(orig) || orig.includes(del.normalized)) {
        matchedDeletions.push({
          file: filePath,
          line: del.lineNum,
          codeSnippet: del.content,
          role: 'REVERTED_LINE',
        });
        break;
      }
    }
  }

  // Check 2: Did PR re-introduce lines that the original fix removed?
  const originalRemovedNormalized = new Set(
    params.originalRemovedLines.map(normalizeLine).filter((l) => l.length > 3)
  );

  const matchedReintroductions: EvidencePathNode[] = [];
  for (const add of prAddedLines) {
    for (const orig of originalRemovedNormalized) {
      if (add.normalized.includes(orig) || orig.includes(add.normalized)) {
        matchedReintroductions.push({
          file: filePath,
          line: add.lineNum,
          codeSnippet: add.content,
          role: 'REVERTED_LINE',
        });
        break;
      }
    }
  }

  const allRevertEvidence = [...matchedDeletions, ...matchedReintroductions];

  if (allRevertEvidence.length > 0) {
    const isExact = allRevertEvidence.length >= Math.min(1, params.originalAddedLines.length);
    return {
      invariantId: invariant.id,
      advisoryId: invariant.advisoryId,
      verdict: isExact ? 'PROVEN' : 'LIKELY',
      summary: `Inverse-patch detected: PR partially or fully reverts security fix from ${invariant.advisoryId}.`,
      evidencePath: allRevertEvidence,
      details: {
        revertedAddedLines: matchedDeletions.length,
        reintroducedVulnerableLines: matchedReintroductions.length,
      },
      remediation: `Do not undo or delete changes introduced in commit ${invariant.fixCommitSha} (${invariant.advisoryId}).`,
    };
  }

  return null;
}
