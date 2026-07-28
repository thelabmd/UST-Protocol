// SPDX-License-Identifier: Apache-2.0
// ONE place that knows how a README illustration is written, and how a light variant is derived from a dark one.
//
// The diagrams were authored in GitHub's DARK palette, so on a white page they rendered as a black block. The fix is
// a `<picture>` with `prefers-color-scheme` and a second file per panel — which immediately created the defect this
// module exists to prevent: THREE places hardcoded the markdown `![alt](path)` form (the panel generator, the version
// stamper, and the package-enumeration gate), so changing the README's image syntax broke two of them and would have
// silently reverted on the next generator run. Same shape as the deploy sites that each enumerated their own artifact
// set: many places knowing one form is one form too many.
//
// The light file is DERIVED, never hand-maintained. `toLight()` is the whole derivation and a gate re-runs it, so a
// hand-edited light variant fails rather than drifting.

// GitHub Primer dark → light. Not a per-hue substitution: RELATIVE EMPHASIS is preserved. A colour that is LIGHTER
// than its sibling on dark — therefore the more prominent of the two there — becomes DARKER on light. A naive map
// would have collapsed the two blues into one shade and lost the distinction the diagrams draw with them.
export const LIGHT_PALETTE = {
  '#0d1117': '#ffffff',   // canvas
  '#c9d1da': '#1f2328',   // fg, default
  '#8b949e': '#59636e',   // fg, muted
  '#30363d': '#d1d9e0',   // border, subtle
  '#3d444d': '#afb8c1',   // border, stronger
  '#79c0ff': '#0550ae',   // blue, prominent
  '#58a6ff': '#0969da',   // blue, accent
  '#7ee787': '#116329',   // green, prominent
  '#3fb950': '#1a7f37',   // green, standard
  '#d29922': '#9a6700',   // attention
  '#bc8cff': '#8250df',   // purple
  '#f85149': '#cf222e',   // danger
};

/** Derive the light-theme rendering of a dark-theme SVG. Total and deterministic — the gate re-runs it. */
export function toLight(svg) {
  let out = svg;
  for (const [dark, light] of Object.entries(LIGHT_PALETTE)) out = out.replace(new RegExp(dark, 'gi'), light);
  return out;
}

/** Colours in `svg` that the palette does not map — a non-empty result means the derivation is incomplete. */
export function unmappedColours(svg) {
  const known = new Set([...Object.keys(LIGHT_PALETTE), ...Object.values(LIGHT_PALETTE)]);
  return [...new Set(svg.match(/#[0-9a-fA-F]{3,8}/g) || [])].filter((c) => !known.has(c.toLowerCase()));
}

export const lightName = (name) => name + '-light';

// DARK ON BOTH THEMES — a panel that stays ONE artifact with no prefers-color-scheme fork.
//
// `status.svg` was the only member, on the reasoning that a TUI panel is dark on a light page too. The owner reviewed
// the six light panels and asked for the status one as well, so the set is now EMPTY and every panel has a light
// variant. The mechanism stays: it is how a future panel opts out, and it is checked rather than assumed — a dark-only
// panel must have NO light file and must NOT sit in a <picture>, so the exclusion cannot half-apply.
export const DARK_ONLY = new Set();
export const isDarkOnly = (name) => DARK_ONLY.has(name);

// MUST escape: the alt is a long prose description (agents read the alt, not the SVG) and now lives in an HTML
// attribute rather than markdown, where a bare quote would truncate it.
export const escAlt = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
export const unescAlt = (s) => s.replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');

/**
 * The README image block. The fallback `src` is the LIGHT file deliberately: a renderer that ignores `<picture>`
 * (npm, mirrors, plain readers) is almost certainly drawing on white — exactly where the dark artwork failed.
 * GitHub honours `<picture>`, so the dark reading is unaffected.
 */
export function imageBlock(name, alt) {
  // a dark-only panel keeps the plain markdown image: one file, both themes, no fork to drift
  if (isDarkOnly(name)) return `![${alt}](.github/${name}.svg)`;
  return [
    '<picture>',
    `  <source media="(prefers-color-scheme: dark)" srcset=".github/${name}.svg">`,
    `  <source media="(prefers-color-scheme: light)" srcset=".github/${lightName(name)}.svg">`,
    `  <img alt="${escAlt(alt)}" src=".github/${lightName(name)}.svg">`,
    '</picture>',
  ].join('\n');
}

const rx = (s) => s.replace(/[-.[\]{}()*+?^$|\\]/g, '\\$&');

/** Matches the whole image block for a panel — either shape — so a rewrite replaces it entirely rather than nesting. */
export const imageRe = (name) =>
  isDarkOnly(name)
    ? new RegExp('!\\[[^\\]]*\\]\\(\\.github/' + rx(name) + '\\.svg\\)')
    : new RegExp('<picture>\\s*<source[^>]*srcset="\\.github/' + rx(name) + '\\.svg">[\\s\\S]*?</picture>');

/** The alt text of a panel's image block, unescaped — what a consumer of the README actually reads. */
export function altOf(readme, name) {
  const block = imageRe(name).exec(readme);
  if (!block) return null;
  if (isDarkOnly(name)) return (/^!\[([\s\S]*)\]\(/.exec(block[0]) || [])[1] ?? null;
  const m = /<img alt="([\s\S]*?)" src=/.exec(block[0]);
  return m ? unescAlt(m[1]) : null;
}
