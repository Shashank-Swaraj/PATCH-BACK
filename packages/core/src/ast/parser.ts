import { parse as babelParse, ParserOptions } from '@babel/parser';
import * as t from '@babel/types';

export const DEFAULT_PARSER_OPTIONS: ParserOptions = {
  sourceType: 'unambiguous',
  plugins: [
    'typescript',
    'jsx',
    'classProperties',
    'optionalChaining',
    'nullishCoalescingOperator',
    'topLevelAwait',
    'dynamicImport',
    'decorators-legacy',
  ],
  tokens: true,
  createParenthesizedExpressions: true,
};

export interface ParsedFile {
  filePath: string;
  code: string;
  lines: string[];
  ast: t.File;
}

/**
 * Parse JavaScript or TypeScript source code into a Babel AST.
 */
export function parseSource(code: string, filePath: string = 'unknown.js'): ParsedFile {
  const ast = babelParse(code, {
    ...DEFAULT_PARSER_OPTIONS,
    sourceFilename: filePath,
  });

  return {
    filePath,
    code,
    lines: code.split(/\r?\n/),
    ast,
  };
}

/**
 * Extract a source snippet for a given AST node or line range.
 */
export function getSnippet(parsedFile: ParsedFile, startLine: number, endLine: number = startLine): string {
  const clampedStart = Math.max(1, startLine);
  const clampedEnd = Math.min(parsedFile.lines.length, endLine);
  return parsedFile.lines.slice(clampedStart - 1, clampedEnd).join('\n');
}
