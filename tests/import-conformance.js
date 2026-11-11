// The conformance fixtures of the import (tests/fixtures/import): what the desktop application's
// import library makes of each file, which the web vault has to arrive at exactly. Shared by the
// Node tests (import-export.test.js) and the browser suite (e2e.js), so that both hold the same
// code to the same files in the same way.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DIRECTORY = path.join(__dirname, "fixtures", "import");
const EXPECTED_SUFFIX = ".expected.json";

// Every expected file, by name.
function expectedFiles() {
	return fs.readdirSync(DIRECTORY).filter((name) => name.endsWith(EXPECTED_SUFFIX)).sort();
}

function readExpected(name) {
	return JSON.parse(fs.readFileSync(path.join(DIRECTORY, name), "utf8"));
}

// The bytes an expected file's `input` stands for: a file next to it, or parts that are repeated
// (the UTF-8 bytes of each text that many times, one after the other).
function inputBytes(input) {
	if (typeof input.file === "string") { return new Uint8Array(fs.readFileSync(path.join(DIRECTORY, input.file))); }
	return new Uint8Array(Buffer.concat(input.parts.map((part) => Buffer.from(part.text.repeat(part.repeat === undefined ? 1 : part.repeat), "utf8"))));
}

// The same input as something that can be handed to a page: the file in Base64, or the parts
// themselves (a 16 MiB input is built in the page, not sent to it).
function inputForPage(input) {
	if (typeof input.file === "string") { return { base64: fs.readFileSync(path.join(DIRECTORY, input.file)).toString("base64") }; }
	return { parts: input.parts };
}

// Runs the cases of one fixture and returns, for each, the result in the shape of an expected
// file: { refused, line? } for a file that is refused, and otherwise format, label, records,
// unsupported, inTrash, ignoredColumns, counts, extras and candidates.
//
// Self-contained on purpose: under Node it is called with the module (arg.ie) and the bytes
// (arg.input.bytes); in Chromium it is handed to page.evaluate as it stands and finds the module
// the page loaded (window.bitosxImportExport). Returns { needsXmlParser: true } where the file is
// XML and there is no XML parser, which is the case under Node.
function runFixture(arg) {
	var ie = arg.ie || window.bitosxImportExport;
	var bytes;
	if (arg.input.bytes) {
		bytes = arg.input.bytes;
	} else if (typeof arg.input.base64 === "string") {
		var binary = atob(arg.input.base64);
		bytes = new Uint8Array(binary.length);
		for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
	} else {
		var encoder = new TextEncoder();
		var chunks = arg.input.parts.map(function (part) { return encoder.encode(part.text.repeat(part.repeat === undefined ? 1 : part.repeat)); });
		var total = chunks.reduce(function (sum, chunk) { return sum + chunk.length; }, 0);
		bytes = new Uint8Array(total);
		var at = 0;
		chunks.forEach(function (chunk) { bytes.set(chunk, at); at += chunk.length; });
	}

	var results = [];
	for (var c = 0; c < arg.cases.length; c++) {
		var parsed;
		try {
			parsed = ie.parseImport(bytes);
		} catch (e) {
			if (e instanceof ie.XmlParserUnavailable) { return { needsXmlParser: true }; }
			if (!(e instanceof ie.ImportRefused)) { throw e; }
			var refusal = { refused: e.code };
			if (e.line !== null) { refusal.line = e.line; }
			results.push(refusal);
			continue;
		}
		var plan = ie.planImport(parsed, arg.cases[c].vault, arg.cases[c].options);
		results.push({
			format: plan.format,
			label: plan.label,
			records: plan.records,
			unsupported: plan.unsupported,
			inTrash: plan.inTrash,
			ignoredColumns: plan.ignoredColumns,
			counts: plan.counts,
			extras: plan.extras,
			candidates: plan.candidates
		});
	}
	return { results: results };
}

module.exports = { DIRECTORY, EXPECTED_SUFFIX, expectedFiles, readExpected, inputBytes, inputForPage, runFixture };
