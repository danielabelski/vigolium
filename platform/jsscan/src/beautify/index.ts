import debug from 'debug';
import { webcrack } from 'webcrack';

const log = debug('jsscan:beautify');

export interface BeautifyModule {
  path: string;
  content: string;
  isEntry: boolean;
}

export interface BeautifyResult {
  /** Whether the produced document differs meaningfully from the input. */
  changed: boolean;
  /** Detected bundle format: 'webpack', 'browserify', ... or 'none'. */
  format: string;
  /** Number of modules recovered from the bundle (0 when not a bundle). */
  moduleCount: number;
  /** Recovered module paths (e.g. ./src/api.js), for finding evidence. */
  modulePaths: string[];
  /** Final single readable document (module-annotated when a bundle). */
  content: string;
}

// Bundle-runtime markers that make a script worth unpacking even when it is not
// obviously minified (e.g. a pretty-printed but still-bundled chunk).
const BUNDLE_MARKERS =
  /__webpack_require__|webpackChunk|webpackJsonp|self\.__next_f|System\.register|__esModule|Object\.defineProperty\(exports/;

// A minified line is, on average, very long. Real bundles run into the hundreds.
const MINIFIED_AVG_LINE_LEN = 200;
const MIN_WORTH_LEN = 500;

/**
 * looksWorthBeautifying is a cheap pre-gate so we only spend a webcrack pass on
 * scripts that are actually minified or bundled. The authoritative vendor/analytics
 * filtering happens on the Go side before jsscan is ever invoked with --beautify;
 * this is only a "is there anything to unminify/unbundle here" check.
 */
export function looksWorthBeautifying(code: string): boolean {
  if (code.length < MIN_WORTH_LEN) return false;
  if (BUNDLE_MARKERS.test(code)) return true;
  const newlines = (code.match(/\n/g) || []).length;
  const avgLineLen = code.length / (newlines + 1);
  return avgLineLen >= MINIFIED_AVG_LINE_LEN;
}

/**
 * beautifyBundle unminifies and (when a bundle is detected) unpacks the script
 * into per-module source using webcrack. Deobfuscation is intentionally
 * disabled: it requires isolated-vm (which we neither install nor bundle) and is
 * unnecessary for the React/Next SPA bundles this targets, which are minified
 * and webpack/browserify-bundled rather than deliberately obfuscated.
 */
export async function beautifyBundle(code: string): Promise<BeautifyResult> {
  const res = await webcrack(code, {
    deobfuscate: false,
    unminify: true,
    jsx: true,
    mangle: false,
  });

  const modules: BeautifyModule[] = [];
  let format = 'none';
  if (res.bundle) {
    format = res.bundle.type;
    for (const [, mod] of res.bundle.modules) {
      modules.push({ path: mod.path, content: mod.code, isEntry: mod.isEntry });
    }
  }

  let content: string;
  if (modules.length > 0) {
    // Assemble a single readable document, entry module first, each section
    // headed by its recovered path so the reader (and linkfinder) sees real
    // ./src/... / ./pages/... route hints.
    const sorted = [...modules].sort((a, b) =>
      a.isEntry === b.isEntry ? 0 : a.isEntry ? -1 : 1,
    );
    content = sorted
      .map((m) => `// ===== ${m.path}${m.isEntry ? ' (entry)' : ''} =====\n${m.content}`)
      .join('\n\n');
  } else {
    content = res.code;
  }

  const result: BeautifyResult = {
    changed: content.trim() !== code.trim(),
    format,
    moduleCount: modules.length,
    modulePaths: modules.map((m) => m.path),
    content,
  };
  log('format=%s modules=%d changed=%s', result.format, result.moduleCount, result.changed);
  return result;
}
