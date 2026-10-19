import { parseSource } from './ast/parser.js';
import { checkGuardDominance } from './invariants/guard-dominance.js';
import { checkGuardRemoval } from './invariants/guard-removal.js';
import { checkSanitizerSwap } from './invariants/sanitizer-swap.js';
import { checkInversePatch } from './invariants/inverse-patch.js';
import { PatchMemoryStore } from './memory/store.js';
import { PRCheckResult, InvariantViolation, VerdictTier } from './types/analysis.js';
import { SecurityInvariant } from './types/invariant.js';

export interface ScanFileTarget {
  filePath: string;
  currentContent: string;
  diff?: string;
}

export interface EngineScanOptions {
  packageName: string;
  targets: ScanFileTarget[];
  prNumber?: number;
  commitSha?: string;
  memoryStore: PatchMemoryStore;
}

export class PatchbackEngine {
  public static async scanPR(options: EngineScanOptions): Promise<PRCheckResult> {
    const startTime = performance.now();
    const invariants = options.memoryStore.getInvariantsForPackage(options.packageName);

    const violations: InvariantViolation[] = [];
    let passedCount = 0;

    for (const invariant of invariants) {
      let invariantViolated = false;

      for (const target of options.targets) {
        let fileViolation: InvariantViolation | null = null;

        try {
          const parsed = parseSource(target.currentContent, target.filePath);

          if (invariant.type === 'GUARD_DOMINATES' || invariant.type === 'GUARD_BYPASS') {
            fileViolation = checkGuardDominance(parsed, invariant);
          } else if (invariant.type === 'SANITIZER_SWAP') {
            fileViolation = checkSanitizerSwap(parsed, invariant);
          }

          // If there is a diff provided, also check diff-based invariants
          if (!fileViolation && target.diff) {
            if (invariant.type === 'GUARD_REMOVAL' || invariant.type === 'GUARD_DOMINATES') {
              fileViolation = checkGuardRemoval(
                { filePath: target.filePath, patchDiff: target.diff },
                invariant
              );
            }
            if (!fileViolation && invariant.type === 'INVERSE_PATCH') {
              fileViolation = checkInversePatch(target.diff, invariant, target.filePath);
            }
          }
        } catch (err) {
          // If AST parsing fails or file is not valid JS, skip or report review
          console.error(`Failed to parse ${target.filePath}:`, err);
        }

        if (fileViolation) {
          violations.push(fileViolation);
          invariantViolated = true;
          break; // Avoid duplicate reporting of same invariant across files
        }
      }

      if (!invariantViolated) {
        passedCount++;
      }
    }

    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    let overallVerdict: VerdictTier = 'BENIGN';
    if (violations.some((v) => v.verdict === 'PROVEN')) {
      overallVerdict = 'PROVEN';
    } else if (violations.some((v) => v.verdict === 'LIKELY')) {
      overallVerdict = 'LIKELY';
    } else if (violations.some((v) => v.verdict === 'REVIEW')) {
      overallVerdict = 'REVIEW';
    }

    return {
      prNumber: options.prNumber,
      commitSha: options.commitSha,
      totalInvariantsChecked: invariants.length,
      passedInvariantsCount: passedCount,
      violations,
      overallVerdict,
      durationMs,
      timestamp: new Date().toISOString(),
    };
  }
}
