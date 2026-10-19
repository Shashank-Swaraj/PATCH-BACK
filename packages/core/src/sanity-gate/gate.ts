import { parseSource } from '../ast/parser.js';
import { checkGuardDominance } from '../invariants/guard-dominance.js';
import { checkSanitizerSwap } from '../invariants/sanitizer-swap.js';
import { SecurityInvariant } from '../types/invariant.js';
import { InvariantViolation } from '../types/analysis.js';

export interface SanityGateResult {
  passed: boolean;
  failedOnVulnerable: boolean;
  holdsOnFixed: boolean;
  vulnerableViolation?: InvariantViolation | null;
  fixedViolation?: InvariantViolation | null;
  rejectionReason?: string;
}

/**
 * The Sanity Gate tests a candidate invariant against historical vulnerable and fixed code.
 * 
 * Condition:
 * 1. Must FAIL on vulnerable code (detecting the flaw).
 * 2. Must PASS on fixed code (confirming the fix resolves it).
 */
export function runSanityGate(
  candidateInvariant: SecurityInvariant,
  vulnerableSource: string,
  fixedSource: string,
  fileName: string = 'app.js'
): SanityGateResult {
  const vulnParsed = parseSource(vulnerableSource, fileName);
  const fixedParsed = parseSource(fixedSource, fileName);

  let vulnViolation: InvariantViolation | null = null;
  let fixedViolation: InvariantViolation | null = null;

  if (candidateInvariant.type === 'GUARD_DOMINATES' || candidateInvariant.type === 'GUARD_REMOVAL' || candidateInvariant.type === 'GUARD_BYPASS') {
    vulnViolation = checkGuardDominance(vulnParsed, candidateInvariant);
    fixedViolation = checkGuardDominance(fixedParsed, candidateInvariant);
  } else if (candidateInvariant.type === 'SANITIZER_SWAP') {
    vulnViolation = checkSanitizerSwap(vulnParsed, candidateInvariant);
    fixedViolation = checkSanitizerSwap(fixedParsed, candidateInvariant);
  }

  const failedOnVulnerable = vulnViolation !== null;
  const holdsOnFixed = fixedViolation === null;
  const passed = failedOnVulnerable && holdsOnFixed;

  let rejectionReason: string | undefined;
  if (!failedOnVulnerable) {
    rejectionReason = `Sanity gate failed: Invariant was NOT triggered on known vulnerable code (ineffective invariant).`;
  } else if (!holdsOnFixed) {
    rejectionReason = `Sanity gate failed: Invariant was triggered on known fixed code (over-restrictive or invalid guard).`;
  }

  return {
    passed,
    failedOnVulnerable,
    holdsOnFixed,
    vulnerableViolation: vulnViolation,
    fixedViolation,
    rejectionReason,
  };
}
