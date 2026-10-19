import { ParsedFile } from '../ast/parser.js';
import { findSinks, matchesPattern } from '../ast/traversal.js';
import { SecurityInvariant, SanitizerSwapParams } from '../types/invariant.js';
import { InvariantViolation, EvidencePathNode } from '../types/analysis.js';
import * as t from '@babel/types';

export function checkSanitizerSwap(
  parsedFile: ParsedFile,
  invariant: SecurityInvariant
): InvariantViolation | null {
  const params = invariant.params as SanitizerSwapParams;
  const sinks = findSinks(parsedFile, params.sink);

  for (const sink of sinks) {
    const targetArg = sink.node.arguments[params.targetArgumentIndex];
    if (!targetArg) continue;

    // Check if the argument is a CallExpression calling the required sanitizer
    let hasSanitizer = false;
    if (t.isCallExpression(targetArg)) {
      if (matchesPattern(targetArg.callee, params.requiredSanitizer)) {
        hasSanitizer = true;
      }
    }

    if (!hasSanitizer) {
      const argSnippet = parsedFile.lines[sink.line - 1] ?? '';
      const evidence: EvidencePathNode[] = [
        {
          file: parsedFile.filePath,
          line: sink.line,
          codeSnippet: argSnippet.trim(),
          role: 'SINK',
        },
        {
          file: parsedFile.filePath,
          line: sink.line,
          codeSnippet: `Argument #${params.targetArgumentIndex} passed to '${params.sink}' lacks required sanitizer '${params.requiredSanitizer}'`,
          role: 'MISSING_GUARD',
        },
      ];

      return {
        invariantId: invariant.id,
        advisoryId: invariant.advisoryId,
        verdict: 'PROVEN',
        summary: `Sanitizer bypassed or swapped: Sink '${params.sink}' called without required sanitizer '${params.requiredSanitizer}'`,
        evidencePath: evidence,
        details: {
          sink: params.sink,
          expectedSanitizer: params.requiredSanitizer,
          argIndex: params.targetArgumentIndex,
        },
        remediation: `Wrap argument with '${params.requiredSanitizer}(...)' before passing to '${params.sink}'. Reference: ${invariant.advisoryId}.`,
      };
    }
  }

  return null;
}
