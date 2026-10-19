import { PRCheckResult, InvariantViolation } from '../types/analysis.js';
import { AdvisoryRecord } from '../types/advisory.js';

export function formatGitHubPRComment(
  result: PRCheckResult,
  advisoriesMap: Record<string, AdvisoryRecord> = {}
): string {
  if (result.overallVerdict === 'BENIGN') {
    return `### 🛡️ PATCHBACK Security Regression Intelligence

✅ **All Security Invariants Preserved** (${result.passedInvariantsCount}/${result.totalInvariantsChecked} checked in ${result.durationMs}ms)

No historical security fixes were regressed or bypassed in this Pull Request.
`;
  }

  const badgeColor = result.overallVerdict === 'PROVEN' ? 'critical' : 'warning';
  let md = `### 🚨 PATCHBACK Security Regression Detected\n\n`;
  md += `> **Verdict:** **\`${result.overallVerdict} REGRESSION\`** | Checked ${result.totalInvariantsChecked} invariants in **${result.durationMs}ms**\n\n`;
  md += `This Pull Request re-introduces a vulnerability previously patched in this repository.\n\n`;

  md += `| Advisory | Invariant ID | Severity | Violated Invariant |\n`;
  md += `| :--- | :--- | :--- | :--- |\n`;

  for (const v of result.violations) {
    const adv = advisoriesMap[v.advisoryId];
    const sev = adv ? adv.severity : 'HIGH';
    md += `| **[${v.advisoryId}](https://github.com/advisories/${v.advisoryId})** | \`${v.invariantId}\` | **${sev}** | ${v.summary} |\n`;
  }

  md += `\n---\n\n`;

  for (let i = 0; i < result.violations.length; i++) {
    const v = result.violations[i];
    const adv = advisoriesMap[v.advisoryId];

    md += `#### 🔍 Violation #${i + 1}: ${v.summary}\n\n`;
    if (adv) {
      md += `* **Historical CVE / Advisory:** [${adv.id}](https://github.com/advisories/${adv.id}) - *${adv.title}*\n`;
      md += `* **Original Fix Commit:** \`${adv.fixCommitSha.substring(0, 7)}\`\n`;
    }

    md += `\n**Evidence Traceback:**\n\`\`\`text\n`;
    for (const node of v.evidencePath) {
      md += `[${node.role}] ${node.file}:${node.line}\n  --> ${node.codeSnippet}\n`;
    }
    md += `\`\`\`\n\n`;

    md += `**Remediation Suggestion:**\n`;
    md += `> ${v.remediation}\n\n`;
  }

  md += `\n---\n*Verified deterministically by **PATCHBACK** (no LLM in the verdict).*`;
  return md;
}
