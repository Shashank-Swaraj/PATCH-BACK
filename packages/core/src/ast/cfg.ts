import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { ParsedFile } from './parser.js';
import { findSinks, findGuards } from './traversal.js';

// Resolve CJS/ESM interop
const runTraverse: any = (traverse as any).default || traverse;

export interface CallPathNode {
  functionName: string;
  file: string;
  line: number;
  snippet: string;
  isEntry: boolean;
  isSink: boolean;
  guardsEncountered: string[];
}

export interface ReachabilityTrace {
  sourceLocation: { file: string; line: number; snippet: string };
  sinkLocation: { file: string; line: number; snippet: string };
  callPath: CallPathNode[];
  isGuardPresent: boolean;
  guardDetails?: string;
}

export class ControlFlowAnalyzer {
  private parsedFile: ParsedFile;

  constructor(parsedFile: ParsedFile) {
    this.parsedFile = parsedFile;
  }

  /**
   * Evaluates if a given sink is dominated by a required guard in all incoming flows.
   */
  public evaluateGuardDominance(
    sinkPattern: string,
    guardPattern: string,
    sourcePattern?: string
  ): {
    dominated: boolean;
    violations: ReachabilityTrace[];
    protectedSinksCount: number;
  } {
    const sinks = findSinks(this.parsedFile, sinkPattern);
    const guards = findGuards(this.parsedFile, guardPattern);
    const violations: ReachabilityTrace[] = [];
    let protectedSinksCount = 0;

    for (const sink of sinks) {
      const sinkLine = sink.line;
      const sinkSnippet = this.parsedFile.lines[sinkLine - 1] ?? '';

      // Check 1: Direct dominance in the same function / scope
      const localGuards = guards.filter((g) => {
        return (
          g.line < sinkLine &&
          g.line >= sink.scopeStartLine &&
          g.line <= sink.scopeEndLine
        );
      });

      const hasDominatingLocalGuard = localGuards.some((g) => g.hasEarlyExit || g.conditionText.includes(guardPattern));

      if (hasDominatingLocalGuard) {
        protectedSinksCount++;
        continue;
      }

      // Check 2: If the sink is in an extracted function, check all callers
      if (sink.enclosingFunctionName) {
        const callerTraces = this.findCallersOfFunction(sink.enclosingFunctionName, guardPattern);
        
        if (callerTraces.length > 0) {
          let allCallersProtected = true;
          for (const trace of callerTraces) {
            if (!trace.isGuardPresent) {
              allCallersProtected = false;
              violations.push({
                sourceLocation: trace.sourceLocation,
                sinkLocation: {
                  file: this.parsedFile.filePath,
                  line: sinkLine,
                  snippet: sinkSnippet.trim(),
                },
                callPath: trace.callPath,
                isGuardPresent: false,
                guardDetails: `Sink '${sinkPattern}' reached via caller '${trace.callPath[0]?.functionName}' without required guard '${guardPattern}'`,
              });
            }
          }
          if (allCallersProtected) {
            protectedSinksCount++;
          }
          continue;
        }
      }

      // If no guard found and not protected:
      violations.push({
        sourceLocation: {
          file: this.parsedFile.filePath,
          line: sinkLine,
          snippet: sinkSnippet.trim(),
        },
        sinkLocation: {
          file: this.parsedFile.filePath,
          line: sinkLine,
          snippet: sinkSnippet.trim(),
        },
        callPath: [
          {
            functionName: sink.enclosingFunctionName || 'anonymous_route',
            file: this.parsedFile.filePath,
            line: sinkLine,
            snippet: sinkSnippet.trim(),
            isEntry: true,
            isSink: true,
            guardsEncountered: [],
          },
        ],
        isGuardPresent: false,
        guardDetails: `Direct call to sink '${sinkPattern}' without guard '${guardPattern}'`,
      });
    }

    return {
      dominated: violations.length === 0,
      violations,
      protectedSinksCount,
    };
  }

  private findCallersOfFunction(targetFunc: string, guardPattern: string): ReachabilityTrace[] {
    const traces: ReachabilityTrace[] = [];
    const file = this.parsedFile;
    const guards = findGuards(file, guardPattern);

    runTraverse(file.ast, {
      CallExpression(path: NodePath<t.CallExpression>) {
        if (t.isIdentifier(path.node.callee) && path.node.callee.name === targetFunc) {
          const callLine = path.node.loc?.start.line ?? 1;
          const callSnippet = file.lines[callLine - 1] ?? '';

          const parentFunction = path.getFunctionParent();
          let callerName = 'top_level';
          let scopeStart = 1;
          let scopeEnd = file.lines.length;

          if (parentFunction && parentFunction.node.loc) {
            scopeStart = parentFunction.node.loc.start.line;
            scopeEnd = parentFunction.node.loc.end.line;

            if (t.isFunctionDeclaration(parentFunction.node) && parentFunction.node.id) {
              callerName = parentFunction.node.id.name;
            } else if (
              t.isCallExpression(parentFunction.parent) &&
              t.isMemberExpression(parentFunction.parent.callee) &&
              t.isIdentifier(parentFunction.parent.callee.property)
            ) {
              // e.g. app.get('/asset', ...)
              const method = parentFunction.parent.callee.property.name;
              const routeArg = parentFunction.parent.arguments[0];
              const routePath = t.isStringLiteral(routeArg) ? routeArg.value : '';
              callerName = `${method}("${routePath}")`;
            }
          }

          // A guard protects this caller ONLY if it is within the same scope and appears before the call
          const callerGuards = guards.filter(
            (g) => g.line < callLine && g.line >= scopeStart && g.line <= scopeEnd
          );
          const isGuardPresent = callerGuards.length > 0;

          traces.push({
            sourceLocation: {
              file: file.filePath,
              line: callLine,
              snippet: callSnippet.trim(),
            },
            sinkLocation: {
              file: file.filePath,
              line: callLine,
              snippet: callSnippet.trim(),
            },
            callPath: [
              {
                functionName: callerName,
                file: file.filePath,
                line: callLine,
                snippet: callSnippet.trim(),
                isEntry: true,
                isSink: false,
                guardsEncountered: callerGuards.map((g) => g.conditionText),
              },
            ],
            isGuardPresent,
          });
        }
      },
    });

    return traces;
  }
}
