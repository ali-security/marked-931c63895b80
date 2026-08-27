const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..', '..');
const redosDir = path.join(rootDir, 'test', 'specs', 'redos');

// Every entry point in package.json that carries its own copy of the grammar:
// "main" (src/marked.js), "browser" (lib/marked.js) and the standalone bundle.
const entryPoints = ['src/marked.js', 'lib/marked.js', 'marked.min.js'];

// https://github.com/advisories/GHSA-rrrm-qjm4-v8hf (CVE-2022-21680)
// cubic backtracking in block.def / block._label.
const cubicDef = require(path.join(redosDir, 'cubic_def.js'));

// https://github.com/advisories/GHSA-5v2h-r2cx-5xgj (CVE-2022-21681)
// exponential backtracking in inline.reflinkSearch / inline.nolink. The link
// definition on the first line is what makes Lexer.inlineTokens enter the
// reflink masking loop, so it is part of the exploit.
const reflinkRedos = {
  markdown: fs.readFileSync(path.join(redosDir, 'reflink_redos.md'), 'utf8'),
  html: fs.readFileSync(path.join(redosDir, 'reflink_redos.html'), 'utf8')
};

const esmBundle = fs.readFileSync(path.join(rootDir, 'lib', 'marked.esm.js'), 'utf8');

// test/specs/run-spec.js fails any spec that needs more than a second; the
// hardened rules render these payloads in well under a millisecond, while the
// vulnerable ones need minutes.
const maxMilliseconds = 1000;

function collapse(html) {
  return html.replace(/\s+/g, ' ').trim();
}

function render(marked, markdown) {
  const before = process.hrtime();
  const html = marked(markdown);
  const elapsed = process.hrtime(before);
  return {
    html: collapse(html),
    milliseconds: elapsed[0] * 1e3 + elapsed[1] * 1e-6
  };
}

describe('ReDOS shipped entry points', () => {
  entryPoints.forEach(entryPoint => {
    describe(entryPoint, () => {
      const marked = require(path.join(rootDir, entryPoint));

      it('does not backtrack on a link definition padded with spaces (CVE-2022-21680)', () => {
        const result = render(marked, cubicDef.markdown);
        expect(result.milliseconds).toBeLessThan(maxMilliseconds);
        expect(result.html).toBe(collapse(cubicDef.html));
      });

      it('does not backtrack on escaped brackets after a link definition (CVE-2022-21681)', () => {
        const result = render(marked, reflinkRedos.markdown);
        expect(result.milliseconds).toBeLessThan(maxMilliseconds);
        expect(result.html).toBe(collapse(reflinkRedos.html));
      });
    });
  });

  describe('lib/marked.esm.js', () => {
    it('ships the hardened block.def rule (CVE-2022-21680)', () => {
      expect(esmBundle).toContain(String.raw`\]: *(?:\n *)?<?([^\s>]+)>?`);
      expect(esmBundle).not.toContain(String.raw`\]: *\n? *<?([^\s>]+)>?`);
    });

    it('ships the hardened reflink and nolink rules (CVE-2022-21681)', () => {
      expect(esmBundle).toContain(String.raw`._label = /(?!\s*\])(?:\\.|[^\[\]\\])+/`);
      expect(esmBundle).toContain(String.raw`reflink: /^!?\[(label)\]\[(ref)\]/`);
      expect(esmBundle).toContain(String.raw`nolink: /^!?\[(ref)\](?:\[\])?/`);
      expect(esmBundle).not.toContain(String.raw`nolink: /^!?\[(?!\s*\])((?:\[[^\[\]]*\]|\\[\[\]]|[^\[\]])*)\](?:\[\])?/`);
    });
  });
});
