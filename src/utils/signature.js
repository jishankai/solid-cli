import { existsSync } from 'fs';

import { executeShellCommand } from './commander.js';

/**
 * Escape a string for safe inclusion as a single-quoted shell argument.
 * @param {string} value
 * @returns {string}
 */
function shellQuote(value) {
  const safe = String(value).replace(/'/g, `'"'"'`);
  return `'${safe}'`;
}

/**
 * Get code signing / Gatekeeper assessment for a local executable.
 *
 * NOTE:
 * - Uses `spctl` (Gatekeeper) and `codesign` outputs.
 * - Returns best-effort results; does not throw.
 * - Uses `cache` (Map) when provided to avoid repeated shell calls.
 *
 * @param {string} filePath
 * @param {Map<string, object>} [cache]
 * @returns {Promise<{
 *   path: string,
 *   exists: boolean,
 *   hasAbsolutePath: boolean,
 *   spctlAccepted: boolean,
 *   spctlOutput: string,
 *   codesignOutput: string,
 *   teamIdentifier: string|null,
 *   authorities: string[],
 *   signedByApple: boolean,
 *   signedByDeveloperId: boolean
 * }>}
 */
export async function getSignatureAssessment(filePath, cache) {
  const rawPath = String(filePath || '');

  // Some collectors may return a path plus args (e.g. "/path/to/bin --flag").
  // If the full string doesn't exist on disk, fall back to first token.
  let path = rawPath;
  if (path.includes(' ') && path.startsWith('/')) {
    const firstToken = path.split(' ')[0];
    if (existsSync(firstToken)) {
      path = firstToken;
    }
  }

  const hasAbsolutePath = path.startsWith('/');
  const exists = hasAbsolutePath ? existsSync(path) : false;

  if (!hasAbsolutePath || !exists) {
    return {
      path: rawPath,
      exists,
      hasAbsolutePath,
      spctlAccepted: false,
      spctlOutput: '',
      codesignOutput: '',
      teamIdentifier: null,
      authorities: [],
      signedByApple: false,
      signedByDeveloperId: false
    };
  }

  if (cache && cache.has(path)) {
    return cache.get(path);
  }

  const quoted = shellQuote(path);

  const spctlOutput = await executeShellCommand(
    `spctl -a -vv --type execute ${quoted} 2>&1 || true`,
    { quiet: true }
  );

  const codesignOutput = await executeShellCommand(
    `codesign -dv --verbose=4 ${quoted} 2>&1 || true`,
    { quiet: true }
  );

  const spctlAccepted = spctlOutput.toLowerCase().includes('accepted');

  const authorities = [];
  let teamIdentifier = null;

  for (const line of codesignOutput.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('Authority=')) {
      authorities.push(trimmed.replace('Authority=', '').trim());
    }
    if (trimmed.startsWith('TeamIdentifier=')) {
      teamIdentifier = trimmed.replace('TeamIdentifier=', '').trim() || null;
    }
  }

  const signedByApple = authorities.some(a => a.toLowerCase().includes('apple'));
  const signedByDeveloperId = authorities.some(a => a.toLowerCase().includes('developer id'));

  const assessment = {
    path,
    exists,
    hasAbsolutePath,
    spctlAccepted,
    spctlOutput,
    codesignOutput,
    teamIdentifier,
    authorities,
    signedByApple,
    signedByDeveloperId
  };

  if (cache) {
    cache.set(path, assessment);
  }

  return assessment;
}
