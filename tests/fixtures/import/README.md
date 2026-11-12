# Import conformance fixtures

Every file in this directory except this one is a copy, **byte for byte**, of
`tests/fixtures/import/` in the desktop application's repository (`networkluki/bitosx`), at commit
`4d746fb1853b998f4b016f14b06b7122070e5f21` (phase 12: authenticator keys). Nothing here is written or edited in this repository.

Each `<input>.expected.json` holds what the desktop's import library (`BitosX.Core.ImportExport`)
makes of its input — for each case (the two choices, and the vault to import into) either the
refusal, or the format, the label, the counts and every candidate as it would be stored. The
expected files are written by the desktop's own tests, never by hand. `generated-*.expected.json`
describe inputs too large or too dull to keep as `parts`: the UTF-8 bytes of each text, repeated.
The format is described in the desktop's `docs/IMPORT_EXPORT.md`, §14.

The web vault has to arrive at exactly the same results:

- `node --test tests/import-export.test.js` holds `vault/public/assets/js/import-export.js` against
  every fixture that needs no XML parser;
- `node tests/e2e.js` holds the same file, as the page loads it, against **all** of them inside
  Chromium (KeePass 2 XML is read with the browser's `DOMParser`, which Node does not have).

Every value in the fixtures is made up.

To update: copy the desktop's directory over this one again (`cp` the files, keep this README),
check with `diff -r` that nothing but this README differs, put the new commit above, and run both
test commands.
