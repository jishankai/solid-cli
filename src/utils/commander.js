import { execa } from 'execa';

/**
 * Execute a shell command and return the result
 * @param {string} command - The command to execute
 * @param {Array} args - Command arguments
 * @param {Object} options - Additional options
 * @param {boolean} options.quiet - Suppress error logging
 * @returns {Promise<string>} - Command output
 */
export async function executeCommand(command, args = [], options = {}) {
  const { quiet = false } = options;
  try {
    const { stdout } = await execa(command, args);
    return stdout;
  } catch (error) {
    if (!quiet) {
      console.error(`Command failed: ${command} ${args.join(' ')}`);
    }
    return '';
  }
}

/**
 * Execute a shell command with shell syntax
 * @param {string} command - The full command string
 * @param {Object} options - Additional options
 * @param {boolean} options.quiet - Suppress error logging
 * @returns {Promise<string>} - Command output
 */
export async function executeShellCommand(command, options = {}) {
  const { quiet = false } = options;
  try {
    const { stdout } = await execa('sh', ['-c', command]);
    return stdout;
  } catch (error) {
    if (!quiet) {
      console.error(`Shell command failed: ${command}`);
    }
    return '';
  }
}
