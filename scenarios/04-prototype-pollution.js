
/**
 * Scenario 04: Prototype Pollution Regression
 *
 * CWE-1321: Improper Control of Object Prototype Attributes
 *
 * Purpose:
 * Verify that PATCHBACK detects the removal of
 * dangerous-property checks from a recursive object merge.
 */

export const scenario = {
  id: 'SCENARIO-04-PROTOTYPE-POLLUTION',
  name: 'Prototype Pollution Guard Removal',
  category: 'Prototype Pollution',
  cwe: 'CWE-1321',
  sink: 'target[key] = source[key]',
  guard: "key === '__proto__' || key === 'constructor' || key === 'prototype'",

  // Step 1: Original vulnerable code
  vulnerableCode: `
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key])
    ) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }

      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}
`,

  // Step 2: Historical security fix
  fixedCode: `
function merge(target, source) {
  for (const key of Object.keys(source)) {

    // Security guard: reject dangerous property names
    if (
      key === '__proto__' ||
      key === 'constructor' ||
      key === 'prototype'
    ) {
      continue;
    }

    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key])
    ) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }

      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}
`,

  // Step 3: Incoming PR removes the historical security guard
  prCode: `
function merge(target, source) {
  for (const key of Object.keys(source)) {

    // Regression: dangerous-property validation is missing.

    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key])
    ) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }

      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}
`,

  // Step 4: Expected analysis outcome
  expectedResult: 'PROVEN_REGRESSION',
};
