/**
 * Ambient declaration for the Agent SDK's own package.json subpath.
 *
 * `version-check.ts` imports `@anthropic-ai/claude-agent-sdk/package.json` to
 * read the bundled bridge's `claudeCodeVersion` at build time. The SDK's
 * `exports` map doesn't list `./package.json`, so TypeScript's bundler-mode
 * resolution rejects the subpath even though bun resolves it fine at runtime.
 * This declaration bridges that gap without loosening resolution globally.
 */
declare module "@anthropic-ai/claude-agent-sdk/package.json" {
  const pkg: {
    version?: string;
    /** claude-code release the vendored control-protocol bridge targets. */
    claudeCodeVersion?: string;
    [key: string]: unknown;
  };
  export default pkg;
}
