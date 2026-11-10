// Unit tests for vault/public/assets/js/import-export.js, run with Node's test runner against the
// very file the browser loads:
//
//   node --test tests/import-export.test.js
//
// The fixtures in tests/fixtures/import are the desktop application's: what its import library
// makes of each file (tests/fixtures/import/README.md). A pass here means the web vault makes the
// same of every one of them that needs no XML parser; the ones that do (KeePass 2 XML is read with
// the browser's DOMParser) are held to the same files in Chromium by tests/e2e.js.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hashwasm = require("../vault/public/assets/vendor/hash-wasm/argon2.umd.min.js");
const vc = require("../vault/public/assets/js/vault-crypto.js")(hashwasm, globalThis.crypto);
const factory = require("../vault/public/assets/js/import-export.js");
const ie = factory(vc);   // no XML parser under Node
const conformance = require("./import-conformance.js");

const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => Buffer.from(bytes).toString("utf8");
const NO_OPTIONS = { copyExtrasToNotes: false, importDuplicates: false };

function refusal(input) {
	const bytes = typeof input === "string" ? utf8(input) : input;
	try { ie.parseImport(bytes); }
	catch (e) {
		assert.ok(e instanceof ie.ImportRefused, `expected a refusal, got ${e && e.name}: ${e && e.message}`);
		return e;
	}
	assert.fail("expected the file to be refused");
}
const refusalCode = (input) => refusal(input).code;
const parse = (input) => ie.parseImport(typeof input === "string" ? utf8(input) : input);
const plan = (input, vault, options) => ie.planImport(parse(input), vault || [], options || NO_OPTIONS);
const candidates = (input, vault, options) => plan(input, vault, options).candidates;
const only = (list) => { assert.equal(list.length, 1); return list[0]; };

// ------------------------------------------------------------- conformance
// The fixtures that cannot run here, and why: they reach the XML parser. (The two with a document
// type declaration are refused on the text, before any parser, and do run.)
const NEEDS_XML_PARSER = [
	"generated-nested-elements-101.expected.json",
	"generated-nested-groups-64.expected.json",
	"generated-nested-groups-65.expected.json",
	"generated-too-many-entries-xml.expected.json",
	"keepass-line-ends.xml.expected.json",
	"keepass.xml.expected.json",
	"refused-damaged.xml.expected.json",
	"refused-not-keepass.xml.expected.json",
	"refused-protected.xml.expected.json"
];

test("conformance: the fixture directory is complete (every input belongs to exactly one expected file)", () => {
	const all = fs.readdirSync(conformance.DIRECTORY).filter((n) => n !== "README.md");
	const expectedFiles = conformance.expectedFiles();
	assert.equal(expectedFiles.length, 44);
	const inputs = all.filter((n) => !n.endsWith(conformance.EXPECTED_SUFFIX)).sort();
	const named = expectedFiles.map((n) => conformance.readExpected(n).input.file).filter((n) => typeof n === "string").sort();
	assert.deepEqual(named, inputs);
	for (const name of expectedFiles) {
		const expected = conformance.readExpected(name);
		assert.equal(expected.schema, 1, name);
		assert.ok(Array.isArray(expected.cases) && expected.cases.length > 0, name);
		if (typeof expected.input.file === "string") { assert.equal(expected.input.file + conformance.EXPECTED_SUFFIX, name); }
		else { assert.ok(Array.isArray(expected.input.parts), name); }
	}
});

const skippedForXml = [];
for (const name of conformance.expectedFiles()) {
	test(`conformance: ${name}`, (t) => {
		const expected = conformance.readExpected(name);
		const out = conformance.runFixture({ ie, input: { bytes: conformance.inputBytes(expected.input) }, cases: expected.cases });
		if (out.needsXmlParser) {
			skippedForXml.push(name);
			t.diagnostic("needs the browser's XML parser: held to this file in Chromium by tests/e2e.js");
			return;
		}
		assert.equal(out.results.length, expected.cases.length);
		expected.cases.forEach((c, i) => {
			assert.deepStrictEqual(out.results[i], c.result, `${name}, case "${c.name}"`);
		});
	});
}

test("conformance: exactly the fixtures that reach the XML parser were left to Chromium, and no other", () => {
	assert.deepEqual(skippedForXml.slice().sort(), NEEDS_XML_PARSER);
});

test("conformance: together the fixtures show every refusal, reason, status, label, extra and kind there is", () => {
	const seen = { refusals: new Set(), reasons: new Set(), statuses: new Set(), labels: new Set(), extras: new Set(), unsupported: new Set(), formats: new Set() };
	for (const name of conformance.expectedFiles()) {
		for (const c of conformance.readExpected(name).cases) {
			const r = c.result;
			if (r.refused) { seen.refusals.add(r.refused); continue; }
			seen.formats.add(r.format);
			seen.labels.add(r.label);
			Object.keys(r.extras).forEach((k) => seen.extras.add(k));
			Object.keys(r.unsupported).forEach((k) => seen.unsupported.add(k));
			r.candidates.forEach((cand) => { seen.statuses.add(cand.status); if (cand.reason) { seen.reasons.add(cand.reason); } });
		}
	}
	// Every refusal but the one that is about the vault, not the file.
	assert.deepEqual([...seen.refusals].sort(), Object.keys(ie.REFUSAL_TEXTS).filter((k) => k !== "vault_item_limit").sort());
	assert.deepEqual([...seen.reasons].sort(), Object.keys(ie.REASON_TEXTS).sort());
	assert.deepEqual([...seen.statuses].sort(), ["add", "duplicate", "not_imported"]);
	assert.deepEqual([...seen.extras].sort(), Object.keys(ie.EXTRA_TEXTS).sort());
	assert.deepEqual([...seen.unsupported].sort(), Object.keys(ie.UNSUPPORTED_TEXTS).sort());
	assert.deepEqual([...seen.formats].sort(), ["bitosx_json", "bitwarden_json", "csv", "keepass_xml"]);
	assert.deepEqual([...seen.labels].sort(), ["BitosX (JSON)", "Bitwarden (CSV)", "Bitwarden (JSON)", "CSV", "Chrome or Edge (CSV)", "Firefox (CSV)", "KeePass 1.x (CSV)", "KeePass 2 (XML)", "KeePassXC (CSV)"]);
});

// ---------------------------------------------------- the text operations (§2.1)
const TRIMMED = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF];

test("trimmed are exactly the characters of the specification, which is more than trim() removes", () => {
	const trimmedByUs = [];
	for (let c = 0; c <= 0xFFFF; c++) {
		if (ie._trim(String.fromCharCode(c)) === "") { trimmedByUs.push(c); }
	}
	assert.deepEqual(trimmedByUs, TRIMMED);
	// Everything JavaScript's own trim removes is in the set, and one character more: U+0085.
	const trimmedByJs = [];
	for (let c = 0; c <= 0xFFFF; c++) { if (String.fromCharCode(c).trim() === "") { trimmedByJs.push(c); } }
	assert.deepEqual(TRIMMED.filter((c) => !trimmedByJs.includes(c)), [0x85]);
	assert.deepEqual(trimmedByJs.filter((c) => !TRIMMED.includes(c)), []);
});

test("trim removes them from both ends and nowhere else; what only looks empty is kept", () => {
	const all = String.fromCharCode(...TRIMMED);
	assert.equal(ie._trim(all + "a" + all + "b" + all), "a" + all + "b");
	assert.equal(ie._trim("plain"), "plain");
	assert.equal(ie._trim(""), "");
	assert.equal(ie._trim(all), "");
	// Not white space: zero-width space and joiners, the Mongolian vowel separator, the information separators.
	for (const c of ["\u200B", "\u200C", "\u200D", "\u2060", "\u180E", "\u001C", "\u001D", "\u001E", "\u001F", "\u0000", "\u007F"]) {
		assert.equal(ie._trim(" " + c + " "), c);
		assert.equal(ie._isBlank(c), false);
	}
	assert.equal(ie._isBlank(""), true);
	assert.equal(ie._isBlank(all), true);
	assert.equal(ie._isBlank(" a "), false);
});

test("lower case changes A to Z and nothing else", () => {
	assert.equal(ie._toLowerAscii("ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`@"), "abcdefghijklmnopqrstuvwxyz[\\]^_`@");
	// toLowerCase() would turn each of these into something else.
	for (const s of ["\u00C9COLE", "\u0130", "\u212A", "\u03A3", "\u1E9E", "\uFF21"]) {
		assert.notEqual(s.toLowerCase(), ie._toLowerAscii(s));
	}
	assert.equal(ie._toLowerAscii("\u00C9COLE"), "\u00C9cole");
	assert.equal(ie._toLowerAscii("\u0130\u212A\u03A3"), "\u0130\u212A\u03A3");
	assert.equal(ie._toLowerAscii("already lower 123"), "already lower 123");
});

test("lines are split at CR LF, at LF and at a CR that no LF follows, and nowhere else", () => {
	assert.deepEqual(ie._splitLines("a\r\nb\nc\rd"), ["a", "b", "c", "d"]);
	assert.deepEqual(ie._splitLines("a\n\rb"), ["a", "", "b"]);
	assert.deepEqual(ie._splitLines("a\r\r\nb"), ["a", "", "b"]);
	assert.deepEqual(ie._splitLines(""), [""]);
	assert.deepEqual(ie._splitLines("one"), ["one"]);
	assert.deepEqual(ie._splitLines("a\n"), ["a", ""]);
	assert.deepEqual(ie._splitLines("a\u2028b\u2029c\u0085d\u000Be\u000Cf"), ["a\u2028b\u2029c\u0085d\u000Be\u000Cf"]);
});

test("a control character is U+0000 to U+001F, or U+007F", () => {
	for (let c = 0; c <= 0x2FF; c++) {
		assert.equal(ie._hasControlCharacter("a" + String.fromCharCode(c) + "b"), c < 0x20 || c === 0x7F, "U+" + c.toString(16));
	}
});

// ---------------------------------------------------------- reading a file (§2)
test("UTF-8 is decoded with or without a byte order mark, and only one mark is removed", () => {
	assert.equal(ie._decodeFile(utf8("r\u00E4ksm\u00F6rg\u00E5s \u65E5\u672C \uD83D\uDD11")), "r\u00E4ksm\u00F6rg\u00E5s \u65E5\u672C \uD83D\uDD11");
	assert.equal(ie._decodeFile(Uint8Array.from([0xEF, 0xBB, 0xBF, 0x61])), "a");
	assert.equal(ie._decodeFile(Uint8Array.from([0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF, 0x61])), "\uFEFFa");
	assert.equal(ie._decodeFile(Uint8Array.from([0x61, 0xEF, 0xBB, 0xBF])), "a\uFEFF");
	assert.equal(ie._decodeFile(new Uint8Array(0)), "");
	assert.equal(ie._decodeFile(Uint8Array.from([0x00])), "\u0000");
});

test("a UTF-16 or UTF-32 byte order mark is refused as an encoding, before anything else", () => {
	for (const bom of [[0xFF, 0xFE], [0xFE, 0xFF], [0x00, 0x00, 0xFE, 0xFF], [0xFF, 0xFE, 0x00, 0x00]]) {
		assert.equal(refusalCode(Uint8Array.from(bom.concat([0x6E, 0x00, 0x61, 0x00]))), "unsupported_encoding");
		assert.equal(refusalCode(Uint8Array.from(bom)), "unsupported_encoding");
	}
});

test("bytes that are not UTF-8 are refused, never replaced", () => {
	const bad = {
		"a lone continuation byte": [0x61, 0x80, 0x62],
		"an overlong form of /": [0xC0, 0xAF],
		"an overlong form of NUL": [0xC0, 0x80],
		"an overlong three-byte form": [0xE0, 0x80, 0xAF],
		"half of a surrogate pair": [0xED, 0xA0, 0x80],
		"the other half": [0xED, 0xB0, 0x80],
		"a pair of surrogates, each encoded": [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80],
		"beyond U+10FFFF": [0xF4, 0x90, 0x80, 0x80],
		"a five-byte form": [0xF8, 0x88, 0x80, 0x80, 0x80],
		"a sequence cut short": [0x61, 0xE2, 0x82],
		"a sequence cut short at the end of a pair": [0xF0, 0x9F, 0x94],
		"0xFF": [0x61, 0xFF],
		"0xFE inside": [0x61, 0xFE, 0x62],
		"Latin-1 text": [0x72, 0xE4, 0x6B, 0x73, 0x6D, 0xF6, 0x72]
	};
	for (const [what, bytes] of Object.entries(bad)) {
		assert.equal(refusalCode(Uint8Array.from([0x6E, 0x61, 0x6D, 0x65, 0x2C].concat(bytes))), "invalid_utf8", what);
	}
});

test("the size is the first thing looked at: 16 MiB is read, one byte more is not", () => {
	assert.equal(ie.LIMITS.maxFileBytes, 16 * 1024 * 1024);
	const atLimit = new Uint8Array(ie.LIMITS.maxFileBytes).fill(0x20);
	atLimit.set(utf8("name,password\nfake,FAKE-pw\n"));
	assert.equal(parse(atLimit).records, 1);
	// One byte more is refused even though it is not text at all (the size is checked before the encoding).
	const over = new Uint8Array(ie.LIMITS.maxFileBytes + 1).fill(0xFF);
	assert.equal(refusalCode(over), "too_large");
});

test("the format is decided by the first character that is not a space, a tab or a line end", () => {
	assert.equal(refusalCode(""), "empty");
	assert.equal(refusalCode(" \t\r\n \n"), "empty");
	assert.equal(refusalCode(Uint8Array.from([0xEF, 0xBB, 0xBF])), "empty");
	assert.equal(refusalCode(" \r\n{"), "invalid_json");
	assert.equal(refusalCode("\t["), "invalid_json");
	assert.equal(refusalCode("\n[]"), "not_recognised");
	// Other white space is not skipped: it is the start of a comma-separated file.
	assert.equal(refusalCode("\u00A0{}"), "no_recognised_columns");
	assert.equal(refusalCode("\u000B{}"), "no_recognised_columns");
	// One byte order mark is removed with the bytes; a second one is text, and so is one further in.
	assert.equal(refusalCode(Uint8Array.from([0xEF, 0xBB, 0xBF, 0x7B, 0x7D])), "not_recognised");
	assert.equal(refusalCode(Uint8Array.from([0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF, 0x7B, 0x7D])), "no_recognised_columns");
	assert.equal(refusalCode(Uint8Array.from([0x20, 0xEF, 0xBB, 0xBF, 0x7B, 0x7D])), "no_recognised_columns");
	assert.equal(refusalCode("name"), "no_recognised_columns");
	// "<" is XML: with a document type declaration it is refused on the text; otherwise it needs a parser.
	assert.equal(refusalCode(" \n<!DOCTYPE KeePassFile><KeePassFile/>"), "doctype");
	assert.throws(() => parse(" <KeePassFile/>"), (e) => e instanceof ie.XmlParserUnavailable && !(e instanceof ie.ImportRefused));
});

test("parseImport takes bytes, and nothing else", () => {
	assert.throws(() => ie.parseImport("name,password\na,b\n"), TypeError);
	assert.throws(() => ie.parseImport(null), TypeError);
	assert.equal(ie.parseImport(Buffer.from("name,password\na,b\n")).records, 1);
});

// ------------------------------------------------- comma-separated records (§3.1)
function records(csv, backslashEscapes) {
	const reader = new ie._CsvRecordReader(csv);
	reader.backslashEscapes = !!backslashEscapes;
	const out = [];
	for (let r = reader.readRecord(); r !== null; r = reader.readRecord()) { out.push(r); }
	return out;
}
function csvRefusal(csv, backslashEscapes) {
	try { records(csv, backslashEscapes); }
	catch (e) { assert.ok(e instanceof ie.ImportRefused); assert.equal(e.code, "invalid_csv"); return e; }
	assert.fail("expected invalid_csv for " + JSON.stringify(csv));
}

test("csv: values are separated by commas, records by CR LF, LF or CR; the last record needs no line end", () => {
	assert.deepEqual(records("a,b,c\n1,2,3\n"), [["a", "b", "c"], ["1", "2", "3"]]);
	for (const t of ["a,b\n1,2\n", "a,b\r\n1,2\r\n", "a,b\r1,2\r", "a,b\n1,2", "a,b\r\n1,2"]) {
		assert.deepEqual(records(t), [["a", "b"], ["1", "2"]], JSON.stringify(t));
	}
});

test("csv: nothing is trimmed, empty values are values, and an empty line is a record of one empty value", () => {
	assert.deepEqual(records(" a ,\tb,c  "), [[" a ", "\tb", "c  "]]);
	assert.deepEqual(records(",,\na,,c\n,b,"), [["", "", ""], ["a", "", "c"], ["", "b", ""]]);
	assert.deepEqual(records("a\n\nb\n"), [["a"], [""], ["b"]]);
	assert.deepEqual(records("\n\n"), [[""], [""]]);
	assert.deepEqual(records(""), []);
	assert.deepEqual(records("a,"), [["a", ""]]);
	assert.deepEqual(records("a,\n"), [["a", ""]]);
	assert.deepEqual(records(","), [["", ""]]);
});

test("csv: a quoted value may hold commas, line ends and doubled quotes, all kept exactly", () => {
	assert.deepEqual(records("\"a,b\",\"line one\nline two\",\"say \"\"hi\"\"\"\nnext,\"\",\n"),
		[["a,b", "line one\nline two", "say \"hi\""], ["next", "", ""]]);
	assert.deepEqual(records("\"a\r\nb\rc\nd\""), [["a\r\nb\rc\nd"]]);
	assert.deepEqual(records("\"  padded  \",\"\",\"\"\"\"\"\""), [["  padded  ", "", "\"\""]]);
	assert.deepEqual(records("\"\uD83D\uDD11 \"\"k\"\"\""), [["\uD83D\uDD11 \"k\""]]);
});

test("csv: a quote that is not the first character, and a backslash, are ordinary characters", () => {
	assert.deepEqual(records("it's 5\" long, \"x\",a\"b"), [["it's 5\" long", " \"x\"", "a\"b"]]);
	assert.deepEqual(records("\"C:\\dir\\file\",a\\\"b"), [["C:\\dir\\file", "a\\\"b"]]);
	assert.deepEqual(records("\"one\\\""), [["one\\"]]);
});

test("csv: a quoted value that is never closed is refused, with the line it starts on", () => {
	assert.equal(csvRefusal("name,password\nA,\"closed\"\nB,\"never closed\nC,x\nD,y\n").line, 3);
	for (const t of ["\"", "a,\"", "\"abc", "\"abc\"\"", "\"a\"\"\"\"b"]) {
		assert.equal(csvRefusal(t).line, 1, JSON.stringify(t));
	}
});

test("csv: anything but a comma or a line end after a closing quote is refused, with its line", () => {
	const cases = [["\"a\"b,c", 1], ["\"a\" ,c", 1], ["x\n\"a\"b", 2], ["x\r\n\"two\nlines\"junk", 3], ["\"a\"\"b\"c\"", 1]];
	for (const [t, line] of cases) { assert.equal(csvRefusal(t).line, line, JSON.stringify(t)); }
	// Lines 1 to 3 are one record; line 4 is blank; the fault is on line 6. A CR LF counts once.
	assert.equal(csvRefusal("\"a\r\nb\rc\"\r\n\r\nok\n\"bad\"x\n").line, 6);
});

test("csv, KeePass 1.x: a backslash makes the next character part of the value, and a quote always closes it", () => {
	assert.deepEqual(records("\"say \\\"hi\\\"\",\"C:\\\\dir\",\"a\\\\\\\"b\",\"\\x\"", true), [["say \"hi\"", "C:\\dir", "a\\\"b", "x"]]);
	assert.deepEqual(records("\"\",\"a\"", true), [["", "a"]]);
	csvRefusal("\"a\"\"b\"", true);
	// A line end after a backslash is still a line end: kept, and counted.
	assert.equal(csvRefusal("\"a\\\nb\"\n\"c\"x", true).line, 3);
	assert.deepEqual(records("\"a\\\nb\"", true), [["a\nb"]]);
	assert.deepEqual(records("\"a\\\r\nb\"", true), [["a\r\nb"]]);
	// A backslash at the very end is refused, with the line the value starts on.
	assert.equal(csvRefusal("x\n\"abc\\", true).line, 2);
	csvRefusal("\"abc\\\"", true);
	// A value that is not quoted is taken as it is.
	assert.deepEqual(records("a\\b,c", true), [["a\\b", "c"]]);
	// The character after the backslash may be half of a pair: the pair stays whole.
	assert.deepEqual(records("\"\\\uD83D\uDD11\"", true), [["\uD83D\uDD11"]]);
});

test("csv: huge values, many records and a million commas are read in one pass", () => {
	const chunk = "x".repeat(62) + "\"\"";
	const quoted = chunk.repeat(15 * 1024 * 1024 / 64);
	const plain = "y".repeat(15 * 1024 * 1024);
	let started = Date.now();
	const record = only(records("\"" + quoted + "\"," + plain + "\n"));
	assert.equal(record[0].length, quoted.length - 15 * 1024 * 1024 / 64);
	assert.equal(record[1].length, plain.length);
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);

	started = Date.now();
	assert.equal(records("a,b,\"c\"\n\n".repeat(300000)).length, 600000);
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);

	started = Date.now();
	const commas = only(records(",".repeat(1000000)));
	assert.equal(commas.length, 1000001);
	assert.ok(commas.every((v) => v === ""));
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

// --------------------------------------------------- comma-separated files (§3.2-3.5)
test("csv: the header is the first record that is not blank; names are trimmed and compared in lower case", () => {
	const p = parse("\n \n,,\n\u00A0\uFEFF\n  NAME\u0085,\tPassWord \nfake,FAKE-pw\n");
	assert.equal(p.format, "csv");
	assert.equal(p.label, "CSV");
	assert.equal(p.records, 1);
	assert.deepEqual(p.entries.map((e) => [e.position, e.name, e.password]), [[1, "fake", "FAKE-pw"]]);
});

test("csv: a file needs a password column and at least one of name, address and username", () => {
	assert.equal(refusalCode("name,url,username\na,b,c\n"), "no_recognised_columns");
	assert.equal(refusalCode("password\nx\n"), "no_recognised_columns");
	assert.equal(refusalCode("password,notes,totp\nx,y,z\n"), "no_recognised_columns");
	assert.equal(refusalCode(",,,\n"), "no_recognised_columns");
	assert.equal(refusalCode("\u00A0\n\u2003\n"), "no_recognised_columns");
	for (const header of ["name,password", "url,password", "username,password", "login_uri,login_password", "account,password", "web site,password"]) {
		assert.equal(parse(header + "\n").records, 0, header);
	}
});

test("csv: each field takes the first name of its list that the header has, the left one of two; everything else is an ignored column", () => {
	// "title" is in the header, but "name" comes first in the list, wherever the columns are.
	const p = parse("title,Name ,uri,URL,password,login_password,username,user name,x, Custom Thing ,,name\nT,N,U1,U2,P1,P2,A,B,c,d,e,N2\n");
	const e = only(p.entries);
	assert.equal(e.name, "N");
	assert.deepEqual(e.addresses, ["U2"]);
	assert.equal(e.password, "P1");
	assert.equal(e.username, "A");
	// In the header's own spelling, trimmed, in the header's order; the nameless column is not listed.
	assert.deepEqual(p.ignoredColumns, ["title", "uri", "login_password", "user name", "x", "Custom Thing", "name"]);
});

test("csv: the alias table of the specification, name by name", () => {
	const fields = {
		name: ["name", "title", "account"],
		addresses: ["url", "urls", "login_uri", "uri", "website", "web site"],
		username: ["username", "login_username", "user name", "login name"],
		password: ["password", "login_password"],
		notes: ["note", "notes", "comments", "extra"],
		totp: ["totp", "login_totp", "otpauth"],
		folder: ["folder", "group", "grouping"]
	};
	for (const [field, names] of Object.entries(fields)) {
		// What a file needs besides the column that is looked at: a password, and one of name, address and username.
		const rest = field === "password" ? ["name"] : ["name", "addresses", "username"].includes(field) ? ["password"] : ["password", "username"];
		for (const column of names) {
			const e = only(parse([column].concat(rest).join(",") + "\nVALUE,other,other\n").entries);
			assert.deepEqual(field === "addresses" ? e.addresses : [e[field]], ["VALUE"], column);
		}
		// Earlier names win over later ones, wherever the columns are.
		for (let i = 1; i < names.length; i++) {
			const e = only(parse([names[i], names[i - 1]].concat(rest).join(",") + "\nlater,EARLIER,other,other\n").entries);
			assert.deepEqual(field === "addresses" ? e.addresses : [e[field]], ["EARLIER"], names[i - 1] + " before " + names[i]);
		}
	}
	for (const column of ["favorite", "fav"]) { assert.equal(only(parse(column + ",name,password\n1,a,b\n").entries).favorite, true, column); }
	assert.deepEqual(only(parse("fields,name,password\nk: v,a,b\n").entries).customFields, [{ name: "k", value: "v" }]);
	assert.deepEqual(parse("type,name,password\nnote,a,b\n").unsupported, { secure_note: 1 });
});

test("csv: the label is the exporter whose header this is exactly, and CSV otherwise", () => {
	const labels = {
		"name,url,username,password,note": "Chrome or Edge (CSV)",
		"name,url,username,password": "Chrome or Edge (CSV)",
		"\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"": "Firefox (CSV)",
		"folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp": "Bitwarden (CSV)",
		"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp": "Bitwarden (CSV)",
		"collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp": "Bitwarden (CSV)",
		"collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp": "Bitwarden (CSV)",
		"\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"": "KeePassXC (CSV)",
		"\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"": "KeePassXC (CSV)",
		"\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"": "KeePass 1.x (CSV)",
		" NAME ,Url,USERNAME,password,Note": "Chrome or Edge (CSV)",
		// One column more, one less, or another order: an ordinary file.
		"name,url,username,password,note,extra": "CSV",
		"url,name,username,password,note": "CSV",
		"name,username,password": "CSV",
		"Title,Url,Username,Password,Notes,OTPAuth": "CSV",   // what 1Password is said to write: no label of its own
		"Account,Login Name,Password,Web Site,Comments,More": "CSV",
		"Login Name,Account,Password,Web Site,Comments": "CSV"
	};
	for (const [header, label] of Object.entries(labels)) { assert.equal(parse(header + "\n").label, label, header); }
});

test("csv: only the exact KeePass 1.x header turns the backslash quoting on, and only for the records after it", () => {
	const row = "\"A \\\"quoted\\\" name\",\"DOMAIN\\\\user\",\"FAKE\\\\pw\",\"\",\"\"\n";
	const keepass = only(parse("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n" + row).entries);
	assert.deepEqual([keepass.name, keepass.username, keepass.password], ["A \"quoted\" name", "DOMAIN\\user", "FAKE\\pw"]);
	// The same columns in another order are read the RFC 4180 way: the same row is damaged there.
	assert.equal(refusalCode("\"Login Name\",\"Account\",\"Password\",\"Web Site\",\"Comments\"\n" + row), "invalid_csv");
	const plain = only(parse("\"Login Name\",\"Account\",\"Password\",\"Web Site\",\"Comments\"\n\"DOMAIN\\\\user\",\"n\",\"FAKE\\\\pw\",\"\",\"\"\n").entries);
	assert.deepEqual([plain.username, plain.password], ["DOMAIN\\\\user", "FAKE\\\\pw"]);
	// The header itself is read the RFC 4180 way: a doubled quote in it is one quote, so it is not that header.
	assert.equal(parse("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\"\"\n").label, "CSV");
});

test("csv: short rows have empty values; a value beyond the last column means the row is not imported; blank records are not rows", () => {
	const p = parse("name,url,username,password\nshort\n\n , ,\u00A0\nfull,https://example.com,fake.user,FAKE-pw\nlong,https://example.com,fake.user,FAKE,pw\nok,https://example.com,fake.user,FAKE-pw,,\n");
	assert.equal(p.records, 4);
	assert.deepEqual(p.entries.map((e) => [e.position, e.name, e.password, e.problem]), [
		[1, "short", "", null], [2, "full", "FAKE-pw", null], [3, "long", "FAKE", "row_has_extra_values"], [4, "ok", "FAKE-pw", null]
	]);
});

test("csv: only the type 'note' is not a login; favorite is 1 or true; both after trimming, in lower case", () => {
	const p = parse("type,favorite,name,password\nnote,,a,b\n NOTE\u0085,,a,b\nNote,,a,b\nnotes,1,n1,p\nlogin, TRUE ,n2,p\n,true\u00A0,n3,p\nsecurenote,yes,n4,p\n2,0,n5,p\n,True,n6,p\n,\u2003 1,n7,p\n,11,n8,p\n");
	assert.equal(p.records, 11);
	assert.deepEqual(p.unsupported, { secure_note: 3 });
	assert.deepEqual(p.entries.map((e) => [e.position, e.name, e.favorite]), [
		[4, "n1", true], [5, "n2", true], [6, "n3", true], [7, "n4", false], [8, "n5", false], [9, "n6", true], [10, "n7", true], [11, "n8", false]
	]);
});

test("csv: Bitwarden's address cell is split at commas, every other address column is one value", () => {
	assert.deepEqual(only(parse("login_uri,login_password\n\"https://a.example/,,b.example, https://c.example/x,y\",p\n").entries).addresses, ["https://a.example/", "", "b.example", " https://c.example/x", "y"]);
	assert.deepEqual(only(parse("uri,password\n\"https://a.example/,b.example\",p\n").entries).addresses, ["https://a.example/", "b.example"]);
	assert.deepEqual(only(parse("url,password\n\"https://a.example/,b.example\",p\n").entries).addresses, ["https://a.example/,b.example"]);
	assert.deepEqual(only(parse("url,password,name\n,p,n\n").entries).addresses, []);
});

test("csv: Bitwarden's custom fields are one a line, split at the last ': '; a line without one is a field without a name", () => {
	const fields = only(parse("fields,name,password\n\"Security question: What: where?\r\nPIN: 0000\n\n  \nno separator here\rspaced name : v \nempty: \n: only a value\ncolon:without space\",a,b\n").entries).customFields;
	assert.deepEqual(fields, [
		{ name: "Security question: What", value: "where?" },
		{ name: "PIN", value: "0000" },
		{ name: "", value: "no separator here" },
		{ name: "spaced name", value: "v " },
		{ name: "empty", value: "" },
		{ name: "", value: "only a value" },
		{ name: "", value: "colon:without space" }
	]);
});

test("csv: 10,000 rows are read and one more refuses the file; blank records and the header do not count", () => {
	const header = "name,password\n";
	const row = "fake,FAKE-pw\n";
	assert.equal(parse(header + (row + "\n,\n").repeat(10000)).records, 10000);
	assert.equal(refusalCode(header + row.repeat(10001)), "too_many_entries");
	// Every record counts, whatever its kind.
	assert.equal(refusalCode("type,name,password\n" + "note,a,b\n".repeat(10001)), "too_many_entries");
	assert.equal(ie.LIMITS.maxEntries, 10000);
});

test("csv: a header of half a million columns is read in one pass", () => {
	const started = Date.now();
	const p = parse("name,password," + "c,".repeat(500000) + "\nfake,FAKE-pw\n");
	assert.equal(p.ignoredColumns.length, 500000);
	assert.equal(only(p.entries).name, "fake");
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

// ------------------------------------------------------------ JSON, strictly (§4.1)
const bitwarden = (items, more) => `{"encrypted": false, ${more ? more + ", " : ""}"items": [${items}]}`;
const login = (members) => `{"type": 1, "name": "Example"${members ? ", " + members : ""}}`;

test("json: damaged JSON is refused as JSON", () => {
	for (const t of ["{", "{\"items\": [", "{\"items\": []", "{\"items\": [],}", "{\"items\": [1,]}", "{'items': []}", "{items: []}",
		"{\"items\": [] /* a comment */}", "{\"items\": []} // a comment", "{\"items\": []} {\"items\": []}", "{\"items\": []} x", "{\"items\": [NaN]}",
		"{\"items\": [01]}", "{\"items\": [\"tab\tin a string\"]}", "{\"items\": [\"bad \\x escape\"]}", "{\"items\": [\"\\u12G4\"]}", "[", "[1, 2",
		"{\"items\": [+1]}", "{\"items\": [1.]}", "{\"items\": [.5]}", "{\"items\": [1e]}", "{\"items\": [Infinity]}", "{\"items\": [undefined]}",
		"{\"items\": [True]}", "{\"items\": [\"\n\"]}", "{\"items\": [\"\\u00\"]}", "{\"items\": []}\uFEFF", "{\"items\": []}\u00A0", "{\"items\": [\u00A0]}",
		"{\"a\" 1}", "{\"a\": }", "{,}", "[,]", "{\"items\": []}}", "{\"items\": []]", "[}", "{]", "{\"items\": [\"unclosed]}", "{\"items\": [\"\\\"]}"]) {
		assert.equal(refusalCode(t), "invalid_json", JSON.stringify(t));
	}
});

test("json: a refusal does not quote the file", () => {
	const refused = refusal("{\"items\": [{\"password\": \"FAKE-secret-marker\" oops}]}");
	assert.equal(refused.code, "invalid_json");
	assert.equal(refused.message, ie.REFUSAL_TEXTS.invalid_json);
	assert.ok(!String(refused.stack || "").includes("FAKE-secret-marker"));
	assert.ok(!JSON.stringify(Object.assign({}, refused)).includes("FAKE-secret-marker"));
	assert.equal(refused.cause, undefined);
});

test("json: a name twice in one object is refused, wherever it is, compared after escapes are resolved", () => {
	for (const t of [
		"{\"items\": [], \"items\": []}",
		"{\"items\": [{\"type\": 1, \"name\": \"a\", \"name\": \"b\"}]}",
		"{\"items\": [], \"unread\": {\"deep\": [{\"x\": 1, \"x\": 2}]}}",
		"{\"items\": [{\"type\": 1, \"login\": {\"password\": \"FAKE-1\", \"password\": \"FAKE-2\"}}]}",
		"{\"encrypted\": true, \"encrypted\": false, \"items\": []}",
		"{\"items\": [], \"\\u0069tems\": []}",
		"{\"format\": \"bitosx-export\", \"version\": 1, \"version\": 2, \"items\": []}",
		"{\"items\": [], \"\": 1, \"\": 2}",
		"{\"items\": [], \"a\\nb\": 1, \"a\\u000ab\": 2}",
		"{\"items\": [], \"\\/\": 1, \"/\": 2}",
		"{\"items\": [], \"\\\\\": 1, \"\\u005c\": 2}",
		"{\"items\": [], \"\\uD83D\\uDD11\": 1, \"\uD83D\uDD11\": 2}",
		"{\"items\": [], \"__proto__\": 1, \"__proto__\": 2}",
		"{\"items\": [], \"a\": {\"b\": [1, {\"c\": {}, \"c\": {}}]}}",
		"[{\"a\": 1, \"a\": 1}]"
	]) {
		assert.equal(refusalCode(t), "invalid_json", t);
	}
});

test("json: the same name in two objects, in a string value or in an array is nothing special", () => {
	assert.equal(parse(bitwarden(login("\"notes\": \"a\"") + "," + login("\"notes\": \"b\""))).entries.length, 2);
	assert.equal(parse("{\"items\": [], \"a\": {\"a\": {\"a\": [\"a\", \"a\", {\"a\": \"a\"}]}}, \"b\": \"items\", \"c\": [\"items\", \"items\"]}").records, 0);
	// Different names that only look alike: a capital, a composed and a decomposed letter, a trailing space.
	assert.equal(parse("{\"items\": [], \"Items\": 1, \"items \": 2, \"\u00E9\": 3, \"e\u0301\": 4, \"\\u00e9 \": 5}").records, 0);
	// A name that looks like a prototype member is a name like any other.
	assert.equal(parse("{\"items\": [], \"__proto__\": 1, \"constructor\": 2, \"toString\": 3, \"hasOwnProperty\": 4}").records, 0);
});

test("json: 64 arrays and objects inside one another are read, 65 are refused", () => {
	const nested = (levels) => "{\"items\": [], \"deep\": " + "[".repeat(levels - 1) + "]".repeat(levels - 1) + "}";
	assert.equal(parse(nested(64)).entries.length, 0);
	assert.equal(refusalCode(nested(65)), "invalid_json");
	assert.equal(refusalCode("[".repeat(65) + "]".repeat(65)), "invalid_json");
	assert.equal(refusalCode("[".repeat(64) + "]".repeat(64)), "not_recognised");
	const objects = (levels) => "{\"items\": [], \"d\": " + "{\"d\": ".repeat(levels - 2) + "{}" + "}".repeat(levels - 2) + "}";
	assert.equal(parse(objects(64)).entries.length, 0);
	assert.equal(refusalCode(objects(65)), "invalid_json");
	// Depth is about what is open at once, not about how many there are.
	assert.equal(parse("{\"items\": [], \"wide\": [" + "[[[]]],".repeat(50000) + "[]]}").entries.length, 0);
	// Brackets inside strings are text.
	assert.equal(parse("{\"items\": [], \"s\": \"" + "[{".repeat(500) + "\"}").entries.length, 0);
	assert.equal(ie.LIMITS.maxJsonDepth, 64);
});

test("json: a million levels are refused at once, without being handed to JSON.parse", () => {
	const started = Date.now();
	assert.equal(refusalCode("[".repeat(1000000)), "invalid_json");
	assert.equal(refusalCode("{\"items\":" + "{\"a\":".repeat(1000000)), "invalid_json");
	assert.equal(refusalCode("[".repeat(1000000) + "]".repeat(1000000)), "invalid_json");
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test("json: half of a surrogate pair is refused, wherever it is", () => {
	for (const t of [
		"{\"items\": [], \"unread\": \"\\uD83D\"}",                        // a high half and nothing after it
		"{\"items\": [], \"unread\": \"\\uDE00\"}",                        // a low half on its own
		"{\"items\": [], \"unread\": \"\\uDE00\\uD83D\"}",                 // the two halves the wrong way round
		"{\"items\": [], \"unread\": \"\\uD83Dx\\uDE00\"}",                // something between them
		"{\"items\": [], \"unread\": \"\\uD83D\\n\\uDE00\"}",
		"{\"items\": [], \"unread\": \"\\uD83D\\uD83D\\uDE00\"}",          // two high halves
		"{\"items\": [], \"\\uD83D\": 1}",                                // in a name
		"{\"items\": [{\"type\": 1, \"name\": \"half \\uD800\"}]}",
		"{\"format\": \"bitosx-export\", \"version\": 1, \"items\": [{\"type\": \"login\", \"password\": \"FAKE \\uDBFF\"}]}",
		"{\"items\": [], \"deep\": [[{\"a\": [\"ok\", \"\\udc00\"]}]]}",
		"{\"items\": [], \"unread\": \"\\uD83D\uD83D\uDD11\"}",            // an escaped half before a whole character
		"{\"items\": [], \"unread\": \"\uD83D\uDD11\\uDD11\"}"
	]) {
		assert.equal(refusalCode(t), "invalid_json", t);
	}
});

test("json: a whole surrogate pair written as escapes is read", () => {
	const e = only(parse(bitwarden("{\"type\": 1, \"name\": \"smile \\uD83D\\uDE00 and \\\\uD83D as text\", \"login\": {\"password\": \"FAKE-\\u00E9-\\uD83D\\uDE00\\ud83d\\ude01\"}}")).entries);
	assert.equal(e.name, "smile \uD83D\uDE00 and \\uD83D as text");
	assert.equal(e.password, "FAKE-\u00E9-\uD83D\uDE00\uD83D\uDE01");
});

test("json: the check for half pairs reads escapes the way JSON does", () => {
	const cases = [["", false], ["plain", false], ["\\n\\t\\\"\\\\", false], ["\\\\uD83D", false], ["\\u00e9\\u0041", false], ["\\uD83D\\uDE00", false],
		["\\ud83d\\ude00\\uD83D\\uDE01", false], ["\\uD83D", true], ["\\uDE00", true], ["\\uD83Dx\\uDE00", true], ["\\uD83D\\\\uDE00", true],
		["\\uD83D\\u0041", true], ["x\\uDBFF", true], ["\\uDC00\\uD800", true], ["\\\\\\uD83D", true], ["\\\\\\\\uD83D", false], ["\\/\\b\\f\\r", false]];
	for (const [escaped, unpaired] of cases) {
		const document = "{\"items\": [], \"s\": \"" + escaped + "\"}";
		if (unpaired) { assert.throws(() => ie._checkJsonText(document), (e) => e instanceof ie.ImportRefused && e.code === "invalid_json", escaped); }
		else { assert.doesNotThrow(() => ie._checkJsonText(document), escaped); }
	}
});

// The same three questions asked another way: parse first, then look at the value. Only possible
// where JSON.parse copes with the document, which is why the check does not work like this.
function referenceVerdict(document) {
	let value;
	try { value = JSON.parse(document); } catch (e) { return "invalid"; }
	const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;
	let deepest = 0, half = false;
	(function walk(v, depth) {
		if (typeof v === "string") { half = half || lone.test(v); return; }
		if (v === null || typeof v !== "object") { return; }
		deepest = Math.max(deepest, depth);
		if (Array.isArray(v)) { v.forEach((x) => walk(x, depth + 1)); return; }
		for (const k of Object.keys(v)) { half = half || lone.test(k); walk(v[k], depth + 1); }
	})(value, 1);
	return half || deepest > 64 ? "refused" : "fine";
}
// A JSON document without a name twice, written with a random mix of raw and escaped characters.
function randomJson(random) {
	const int = (n) => Math.floor(random() * n);
	const pick = (list) => list[int(list.length)];
	const pieces = ["a", "b", "\"", "\\", "/", "\n", "\t", "{", "}", "[", "]", ",", ":", " ", "\u00E9", "\u2028", "\uD83D\uDD11", "\\u", "u", "D83D", "\uD83D", "\uDD11", "\uD800", "\uDFFF", "\u0000", "x"];
	const string = () => {
		let raw = "";
		for (let i = 0, n = int(5); i < n; i++) { raw += pick(pieces); }
		let out = "\"";
		for (const unit of raw.split("")) {
			const c = unit.charCodeAt(0);
			if (c === 0x22 || c === 0x5C || c < 0x20) { out += c === 0x0A && int(2) ? "\\n" : c === 0x22 && int(2) ? "\\\"" : c === 0x5C && int(2) ? "\\\\" : "\\u" + c.toString(16).padStart(4, "0"); }
			else if (c === 0x2F && int(2)) { out += "\\/"; }
			else if ((c >= 0xD800 && c <= 0xDFFF) || int(6) === 0) { out += "\\u" + (int(2) ? c.toString(16).toUpperCase() : c.toString(16)).padStart(4, "0"); }
			else { out += unit; }
		}
		return out + "\"";
	};
	const value = (depth) => {
		const k = int(depth > 5 ? 4 : 7);
		if (k === 0) { return pick(["null", "true", "false"]); }
		if (k === 1) { return pick(["0", "-1", "1.5", "1e3", "2E-2", "10"]); }
		if (k <= 3) { return string(); }
		const ws = () => pick(["", "", " ", "\n", "\t\r\n"]);
		if (k === 4) { const items = []; for (let i = 0, n = int(4); i < n; i++) { items.push(value(depth + 1)); } return "[" + ws() + items.join(ws() + "," + ws()) + ws() + "]"; }
		const members = [];
		for (let i = 0, n = int(4); i < n; i++) { members.push("\"k" + i + (int(3) ? "" : "\\u0041") + "\"" + ws() + ":" + ws() + value(depth + 1)); }
		return "{" + ws() + members.join(ws() + "," + ws()) + ws() + "}";
	};
	return value(0);
}
function seeded(seed) {
	let a = seed >>> 0;
	return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

test("json: on 20,000 generated documents the check agrees with parsing first and looking afterwards", () => {
	const random = seeded(20261110);
	let fine = 0, refused = 0;
	for (let i = 0; i < 20000; i++) {
		const document = randomJson(random);
		const expected = referenceVerdict(document);
		assert.notEqual(expected, "invalid", "the generator writes valid JSON: " + JSON.stringify(document));
		let got = "fine";
		try { ie._checkJsonText(document); } catch (e) { assert.ok(e instanceof ie.ImportRefused); got = "refused"; }
		assert.equal(got, expected, JSON.stringify(document));
		if (expected === "fine") { fine++; assert.deepStrictEqual(ie._parseJsonStrict(document), JSON.parse(document)); } else { refused++; }
	}
	assert.ok(fine > 3000 && refused > 3000, `${fine} fine, ${refused} refused`);
});

test("json: a name twice is found in generated documents, at any depth and however it is escaped", () => {
	const random = seeded(7);
	const int = (n) => Math.floor(random() * n);
	const spellings = (name) => [name, name.split("").map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""), "\\u" + name.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0") + name.slice(1)];
	for (let i = 0; i < 2000; i++) {
		const name = ["a", "name", "k0", "\u00E9", "/", "\uD83D\uDD11"][int(6)];
		const first = spellings(name)[int(3)], second = spellings(name)[int(3)];
		const twice = "{\"" + first + "\": " + randomJson(random) + ", \"other\": 1, \"" + second + "\": 2}";
		let document = twice;
		for (let d = int(6); d > 0; d--) { document = int(2) ? "[" + randomJson(random) + ", " + document + "]" : "{\"x\": " + document + ", \"y\": 0}"; }
		if (referenceVerdict(document) === "invalid") { continue; }
		assert.throws(() => ie._checkJsonText(document), (e) => e instanceof ie.ImportRefused && e.code === "invalid_json", document);
	}
});

test("json: may start with a byte order mark and white space", () => {
	const file = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(" \r\n\t" + bitwarden(login("\"login\": {\"password\": \"FAKE-pw\"}")) + "\n")]);
	assert.equal(only(parse(file).entries).password, "FAKE-pw");
});

// --------------------------------------------------------- the two JSON formats (§4, §6)
test("json: which format it is — BitosX first, then encrypted, then items", () => {
	for (const t of ["{}", "{\"items\": {}}", "{\"items\": null}", "{\"format\": \"something-else\", \"version\": 1}", "{\"format\": \"BITOSX-EXPORT\", \"version\": 1}",
		"{\"logins\": [{\"name\": \"x\"}]}", "[]", "[{\"name\": \"Example\", \"password\": \"FAKE-pw\"}]", "[[[]]]", "{\"encrypted\": false}", "{\"format\": 1}"]) {
		assert.equal(refusalCode(t), "not_recognised", t);
	}
	// A file that says it is BitosX's is read as BitosX's, whatever else it says.
	assert.equal(parse("{\"encrypted\": true, \"format\": \"bitosx-export\", \"version\": 1, \"items\": []}").format, "bitosx_json");
	// Only the value true means encrypted.
	assert.equal(refusalCode("{\"encrypted\": true, \"items\": []}"), "encrypted_export");
	assert.equal(refusalCode("{\"encrypted\": true, \"passwordProtected\": true, \"salt\": \"x\", \"data\": \"y\"}"), "encrypted_export");
	for (const v of ["false", "\"true\"", "1", "null", "[true]"]) { assert.equal(parse("{\"encrypted\": " + v + ", \"items\": []}").format, "bitwarden_json", v); }
	assert.equal(parse("{\"items\": []}").label, "Bitwarden (JSON)");
});

test("bitwarden: a login with everything is read as Bitwarden writes it", () => {
	const p = parse(`{"encrypted": false, "folders": [{"id": "f-1", "name": "Work"}, {"id": "f-1", "name": "Second with the same id"}, {"id": "", "name": "No id"}, "nonsense"],
		"items": [{"id": "i-1", "folderId": "f-1", "type": 1, "name": " Example ", "notes": "n", "favorite": true, "reprompt": 0,
			"fields": [{"name": " PIN ", "value": "0000", "type": 0}, {"name": "linked", "type": 3, "linkedId": 100}, "nonsense", {"value": "nameless"}],
			"login": {"username": " fake.user ", "password": " FAKE pw ", "totp": "FAKESECRET", "fido2Credentials": [{"credentialId": "x"}],
				"uris": [{"match": null, "uri": "https://example.com/login"}, {"uri": ""}, {"uri": null}, "nonsense", {"uri": "androidapp://com.example"}]},
			"passwordHistory": [{"lastUsedDate": "2026-01-01T00:00:00.000Z", "password": "FAKE-old"}], "collectionIds": null}]}`);
	assert.equal(p.records, 1);
	assert.deepEqual(only(p.entries), {
		position: 1, name: " Example ", username: " fake.user ", password: " FAKE pw ", notes: "n", favorite: true,
		addresses: ["https://example.com/login", "androidapp://com.example"], totp: "FAKESECRET", folder: "Work",
		customFields: [{ name: "PIN", value: "0000" }, { name: "linked", value: "" }, { name: "", value: "nameless" }], problem: null
	});
});

test("bitwarden: kinds are told by the number, written any way JSON allows; everything else is counted and left out", () => {
	const kinds = { 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key", 6: "bank_account", 7: "drivers_license", 8: "passport", 9: "other", 0: "other", "-1": "other", "1.5": "other", "1e999": "other", "2.5": "other", "100": "other" };
	for (const [type, kind] of Object.entries(kinds)) {
		const p = parse(bitwarden(`{"type": ${type}, "name": "x"}`));
		assert.deepEqual(p.unsupported, { [kind]: 1 }, type);
		assert.equal(p.entries.length, 0);
		assert.equal(p.records, 1);
	}
	for (const type of ["1", "1.0", "1e0", "10e-1", "0.1E+1", "1.00000000000000000001", "100e-2"]) {
		assert.equal(parse(bitwarden(`{"type": ${type}, "name": "x"}`)).entries.length, 1, type);
	}
	for (const type of ["2.0", "20e-1"]) { assert.deepEqual(parse(bitwarden(`{"type": ${type}}`)).unsupported, { secure_note: 1 }, type); }
	// Not a number, or no type, or not an object at all: other.
	for (const item of ["{\"name\": \"no type\"}", "{\"type\": \"1\"}", "{\"type\": null}", "{\"type\": true}", "{\"type\": [1]}", "{\"type\": {}}", "null", "1", "\"login\"", "[]", "true"]) {
		assert.deepEqual(parse(bitwarden(item)).unsupported, { other: 1 }, item);
	}
	// In the order of the fixtures, kinds with none absent.
	const mixed = parse(bitwarden([9, 3, 2, 8, 2, 5].map((t) => `{"type": ${t}}`).join(",")));
	assert.deepEqual(Object.entries(mixed.unsupported), [["secure_note", 2], ["card", 1], ["ssh_key", 1], ["passport", 1], ["other", 1]]);
});

test("bitwarden: an item in the trash is counted and left out, whatever it is; an archived item is an ordinary item", () => {
	for (const deleted of ["\"2026-01-01T00:00:00.000Z\"", "\"\"", "false", "0", "{}", "[]"]) {
		const p = parse(bitwarden(`{"type": 1, "name": "x", "deletedDate": ${deleted}}, {"type": 3, "deletedDate": ${deleted}}, {"deletedDate": ${deleted}}`));
		assert.equal(p.inTrash, 3, deleted);
		assert.equal(p.entries.length, 0);
		assert.deepEqual(p.unsupported, {});
		assert.equal(p.records, 3);
	}
	assert.equal(parse(bitwarden("{\"type\": 1, \"name\": \"x\", \"deletedDate\": null}")).entries.length, 1);
	assert.equal(parse(bitwarden("{\"type\": 1, \"name\": \"x\", \"archivedDate\": \"2026-01-01T00:00:00.000Z\"}")).entries.length, 1);
});

test("bitwarden: a member that is absent, null or of another type counts as absent", () => {
	const absent = { position: 1, name: "", username: "", password: "", notes: "", favorite: false, addresses: [], totp: "", folder: "", customFields: [], problem: null };
	for (const item of [
		"{\"type\": 1}",
		"{\"type\": 1, \"name\": null, \"notes\": null, \"favorite\": null, \"login\": null, \"fields\": null, \"folderId\": null}",
		"{\"type\": 1, \"name\": 5, \"notes\": [\"n\"], \"favorite\": \"true\", \"login\": \"l\", \"fields\": {}, \"folderId\": 7}",
		"{\"type\": 1, \"favorite\": 1, \"login\": {\"username\": 1, \"password\": false, \"totp\": {}, \"uris\": {\"uri\": \"https://example.com\"}}}",
		"{\"type\": 1, \"login\": {\"uris\": [null, 5, \"https://example.com\", [], {\"uri\": 5}, {\"uri\": null}, {}]}, \"fields\": [null, 5, \"x\", []]}",
		"{\"type\": 1, \"login\": []}"
	]) {
		assert.deepEqual(only(parse(bitwarden(item)).entries), absent, item);
	}
});

test("bitwarden: a folder is found by its id exactly, and names that look like prototype members are only names", () => {
	const folders = "\"folders\": [{\"id\": \"A\", \"name\": \"Upper\"}, {\"id\": \"a\", \"name\": \"lower\"}, {\"id\": \"__proto__\", \"name\": \"Proto\"}, {\"id\": \"toString\", \"name\": \"ToString\"}, {\"id\": \"n\"}]";
	const folderOf = (id) => only(parse(bitwarden(`{"type": 1, "name": "x", "folderId": ${id}}`, folders)).entries).folder;
	assert.equal(folderOf("\"A\""), "Upper");
	assert.equal(folderOf("\"a\""), "lower");
	assert.equal(folderOf("\"__proto__\""), "Proto");
	assert.equal(folderOf("\"toString\""), "ToString");
	assert.equal(folderOf("\"constructor\""), "");
	assert.equal(folderOf("\"hasOwnProperty\""), "");
	assert.equal(folderOf("\"n\""), "");
	assert.equal(folderOf("\" a\""), "");
	assert.equal(folderOf("\"\""), "");
	// Without folders, or with folders that are not an array, there is none.
	assert.equal(only(parse(bitwarden("{\"type\": 1, \"name\": \"x\", \"folderId\": \"a\"}", "\"folders\": {\"a\": \"b\"}")).entries).folder, "");
	// A member named __proto__ is a member like any other, and gives the item nothing.
	const inherited = only(parse(bitwarden("{\"type\": 1, \"__proto__\": {\"name\": \"from the prototype\", \"login\": {\"password\": \"FAKE-inherited\"}}}")).entries);
	assert.equal(inherited.name, "");
	assert.equal(inherited.password, "");
});

test("json: only a member an object has itself is read, whatever every object inherits", () => {
	// Another script that had added members to Object.prototype would otherwise add them to every item of a file.
	const polluted = { name: "FAKE-inherited", notes: "FAKE-inherited", favorite: true, folderId: "f", deletedDate: "2026-01-01", type: 1, encrypted: true, format: "bitosx-export", version: 1,
		login: { username: "FAKE-inherited", password: "FAKE-inherited", totp: "FAKE", uris: [{ uri: "https://inherited.example" }] }, fields: [{ name: "n", value: "v" }], urls: ["https://inherited.example"],
		username: "FAKE-inherited", password: "FAKE-inherited", uri: "https://inherited.example", value: "FAKE-inherited", id: "f", items: [{ type: 1 }], folders: [{ id: "f", name: "Inherited" }] };
	const names = Object.keys(polluted);
	try {
		for (const n of names) { Object.defineProperty(Object.prototype, n, { value: polluted[n], configurable: true, writable: true, enumerable: false }); }
		assert.equal(refusalCode("{}"), "not_recognised");
		const p = parse("{\"items\": [{\"type\": 1, \"login\": {}, \"fields\": [{}]}, {}, {\"type\": 2}], \"folders\": [{}]}");
		assert.equal(p.format, "bitwarden_json");
		assert.equal(p.inTrash, 0);
		assert.deepEqual(Object.assign({}, p.unsupported), { secure_note: 1, other: 1 });
		assert.deepEqual(only(p.entries).customFields.map((f) => [f.name, f.value]), [["", ""]]);
		assert.deepEqual([only(p.entries).name, only(p.entries).username, only(p.entries).password, only(p.entries).notes, only(p.entries).favorite, only(p.entries).folder, only(p.entries).totp, only(p.entries).addresses.length],
			["", "", "", "", false, "", "", 0]);
		assert.equal(refusalCode("{\"format\": \"bitosx-export\"}"), "unsupported_version");
		const own = parse("{\"format\": \"bitosx-export\", \"version\": 1, \"items\": [{\"type\": \"login\"}, {}]}");
		assert.deepEqual([only(own.entries).name, only(own.entries).password, only(own.entries).addresses.length, own.unsupported.other], ["", "", 0, 1]);
	} finally {
		for (const n of names) { delete Object.prototype[n]; }
	}
	assert.equal(({}).name, undefined);
});

test("bitwarden and BitosX: 10,000 items are read and one more refuses the file", () => {
	const note = "{\"type\": 2}";
	assert.equal(parse("{\"items\": [" + Array(10000).fill(note).join(",") + "]}").records, 10000);
	assert.equal(refusalCode("{\"items\": [" + Array(10001).fill(note).join(",") + "]}"), "too_many_entries");
	const other = "0";
	assert.equal(parse("{\"format\": \"bitosx-export\", \"version\": 1, \"items\": [" + Array(10000).fill(other).join(",") + "]}").records, 10000);
	assert.equal(refusalCode("{\"format\": \"bitosx-export\", \"version\": 1, \"items\": [" + Array(10001).fill(other).join(",") + "]}"), "too_many_entries");
	// The number of items is asked before anything else about them: an encrypted file says so first.
	assert.equal(refusalCode("{\"encrypted\": true, \"items\": [" + Array(10001).fill(note).join(",") + "]}"), "encrypted_export");
});

test("bitosx: version one is the number 1, however it is written; anything else is a newer version", () => {
	const doc = (version) => `{"format": "bitosx-export"${version === null ? "" : ", \"version\": " + version}, "items": []}`;
	for (const v of ["1", "1.0", "1e0", "10e-1", "1.000"]) { assert.equal(parse(doc(v)).label, "BitosX (JSON)", v); }
	for (const v of ["2", "0", "1.5", "-1", "\"1\"", "null", "true", "[1]", "{}", "1e999", null]) { assert.equal(refusalCode(doc(v)), "unsupported_version", String(v)); }
	// The version is asked before the items.
	assert.equal(refusalCode("{\"format\": \"bitosx-export\", \"version\": 2}"), "unsupported_version");
	for (const t of ["{\"format\": \"bitosx-export\", \"version\": 1}", "{\"format\": \"bitosx-export\", \"version\": 1, \"items\": {}}", "{\"format\": \"bitosx-export\", \"version\": 1, \"items\": null}"]) {
		assert.equal(refusalCode(t), "not_recognised", t);
	}
});

test("bitosx: logins are read leniently, members it does not know are ignored, and anything else is counted as other", () => {
	const p = parse(`{"format": "bitosx-export", "version": 1, "exportedAt": "2026-11-10T12:00:00Z", "future": {"x": 1}, "items": [
		{"type": "login", "name": " Example ", "username": " u ", "password": " p ", "urls": ["https://example.com/", 5, null, "", " example.org ", ["x"]], "notes": " n ", "favorite": true,
			"createdAt": "2025-01-02T03:04:05.1234567Z", "updatedAt": "nonsense", "id": "ignored", "totp": "ignored", "folder": "ignored"},
		{"type": "login"},
		{"type": "login", "name": null, "username": 1, "password": false, "urls": "https://example.com", "notes": {}, "favorite": "true"},
		{"type": "note", "name": "x"}, {"type": 1}, {"name": "no type"}, "login", null, []]}`);
	assert.equal(p.records, 9);
	assert.deepEqual(p.unsupported, { other: 6 });
	assert.equal(p.inTrash, 0);
	assert.deepEqual(p.entries, [
		{ position: 1, name: " Example ", username: " u ", password: " p ", notes: " n ", favorite: true, addresses: ["https://example.com/", "", " example.org "], totp: "", folder: "", customFields: [], problem: null },
		{ position: 2, name: "", username: "", password: "", notes: "", favorite: false, addresses: [], totp: "", folder: "", customFields: [], problem: null },
		{ position: 3, name: "", username: "", password: "", notes: "", favorite: false, addresses: [], totp: "", folder: "", customFields: [], problem: null }
	]);
});

// -------------------------------------------------------------- KeePass 2 XML (§5)
// Node has no XML parser, so the files themselves are read in Chromium (tests/e2e.js). What can be
// held here is everything around the parser: what is refused before it, what it is handed, and
// what is made of the document it returns — with a document put together by hand.
function fakeElement(name, attributes, children) {
	const node = { nodeType: 1, nodeName: name, localName: name.split(":").pop(), namespaceURI: (attributes && attributes.xmlns) || null, firstChild: null, nextSibling: null, children: children || [],
		getAttribute(n) { return attributes && Object.prototype.hasOwnProperty.call(attributes, n) ? attributes[n] : null; } };
	node.children.forEach((child, i) => { child.nextSibling = node.children[i + 1] || null; });
	node.firstChild = node.children[0] || null;
	return node;
}
const E = (name, ...children) => fakeElement(name, null, children.map((c) => typeof c === "string" ? { nodeType: 3, data: c, nextSibling: null } : c));
const EA = (name, attributes, ...children) => fakeElement(name, attributes, children.map((c) => typeof c === "string" ? { nodeType: 3, data: c, nextSibling: null } : c));
const CDATA = (data) => ({ nodeType: 4, data, nextSibling: null });
const COMMENT = (data) => ({ nodeType: 8, data, nextSibling: null });
const S = (key, value, attributes) => E("String", E("Key", key), attributes ? EA("Value", attributes, value) : E("Value", value));
function fakeDocument(root) {
	return {
		documentElement: root,
		getElementsByTagNameNS(ns, local) {
			const found = [];
			(function walk(n) { if (!n || n.nodeType !== 1) { return; } if (n.namespaceURI === ns && n.localName === local) { found.push(n); } n.children.forEach(walk); })(root);
			return found;
		}
	};
}
function withFakeParser(document) {
	const calls = [];
	function FakeParser() {}
	FakeParser.prototype.parseFromString = function (source, type) {
		calls.push({ source, type });
		if (document instanceof Error) { throw document; }
		return document;
	};
	return { xml: factory(vc, FakeParser), calls };
}
function readFake(root, source) {
	const { xml, calls } = withFakeParser(root === null ? null : fakeDocument(root));
	try { return { parsed: xml.parseImport(utf8(source || "<KeePassFile/>")), calls }; }
	catch (e) { if (e instanceof xml.ImportRefused) { return { refused: e.code, calls }; } throw e; }
}

test("xml: a document type declaration is refused on the text, in any letter case and anywhere, before any parser sees it", () => {
	for (const t of ["<!DOCTYPE KeePassFile><KeePassFile/>", "<!doctype x><KeePassFile/>", "<!DocType x><KeePassFile/>", "<KeePassFile><!-- <!DOCTYPE x> --></KeePassFile>",
		"<KeePassFile><![CDATA[<!DOCTYPE x>]]></KeePassFile>", "<KeePassFile a=\"<!DOCTYPE\"/>", "<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [<!ENTITY lol \"lol\">]><KeePassFile>&lol;</KeePassFile>",
		"<KeePassFile/><!DOCTYPE", "<<!<!DOCTYPE", " \n<!dOcTyPe"]) {
		const { xml, calls } = withFakeParser(fakeDocument(E("KeePassFile")));
		assert.throws(() => xml.parseImport(utf8(t)), (e) => e instanceof xml.ImportRefused && e.code === "doctype", t);
		assert.equal(calls.length, 0, "the parser was not called for " + t);
		assert.equal(ie._containsDoctype(t), true);
	}
	// Not that declaration: other letters that only fold to these, the pieces apart, or without the "<!".
	for (const t of ["<KeePassFile>DOCTYPE</KeePassFile>", "<KeePassFile>! DOCTYPE &lt;!DOCTYPE</KeePassFile>", "<! DOCTYPE>", "<!DOCTYP E>", "<!\u0110OCTYPE>", "<!DOCT\u00DDPE>", "<!DOCTYP\u0116>", "<!-- DOC TYPE -->"]) {
		assert.equal(ie._containsDoctype(t), false, t);
	}
});

test("xml: the parser is handed the text without leading spaces, tabs and line ends, as application/xml", () => {
	const { calls } = readFake(E("KeePassFile"), " \r\n\t <KeePassFile>\u00A0</KeePassFile>\n");
	assert.deepEqual(calls, [{ source: "<KeePassFile>\u00A0</KeePassFile>\n", type: "application/xml" }]);
	// A byte order mark is removed with the bytes, before that.
	const bom = withFakeParser(fakeDocument(E("KeePassFile")));
	bom.xml.parseImport(Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from("\n<KeePassFile/>")]));
	assert.equal(bom.calls[0].source, "<KeePassFile/>");
});

test("xml: what the parser could not read is refused as damaged, and its message is not passed on", () => {
	assert.equal(readFake(null).refused, "invalid_xml");
	assert.equal(withFakeParser({ documentElement: null, getElementsByTagNameNS: () => [] }).xml && readFake(null).refused, "invalid_xml");
	// Chromium and Safari: a <parsererror> in the XHTML namespace inside what was read so far.
	assert.equal(readFake(E("KeePassFile", EA("parsererror", { xmlns: "http://www.w3.org/1999/xhtml" }, "error on line 1: FAKE-secret-marker"), E("Root"))).refused, "invalid_xml");
	assert.equal(readFake(EA("html", { xmlns: "http://www.w3.org/1999/xhtml" }, EA("body", { xmlns: "http://www.w3.org/1999/xhtml" }, EA("parsererror", { xmlns: "http://www.w3.org/1999/xhtml" })))).refused, "invalid_xml");
	// Firefox: the document is a <parsererror> in Mozilla's namespace.
	assert.equal(readFake(EA("parsererror", { xmlns: "http://www.mozilla.org/newlayout/xml/parsererror.xml" }, "XML Parsing Error")).refused, "invalid_xml");
	// An element of that name in no namespace is an element like any other.
	assert.equal(readFake(E("KeePassFile", E("parsererror"))).parsed.records, 0);
	// A parser that throws is a parser that could not read the file.
	const thrown = withFakeParser(new Error("FAKE-secret-marker in a parser message"));
	assert.throws(() => thrown.xml.parseImport(utf8("<KeePassFile/>")), (e) => e instanceof thrown.xml.ImportRefused && e.code === "invalid_xml" && !e.message.includes("FAKE-secret-marker"));
});

test("xml: the root element has to be KeePassFile, by its name as written", () => {
	assert.equal(readFake(E("keepassfile")).refused, "not_recognised");
	assert.equal(readFake(E("kp:KeePassFile")).refused, "not_recognised");
	assert.equal(readFake(E("html", E("KeePassFile"))).refused, "not_recognised");
	assert.equal(readFake(EA("KeePassFile", { xmlns: "urn:x" })).parsed.format, "keepass_xml");
	// The name is asked before anything else about the root.
	assert.equal(readFake(EA("Other", { Protected: "True" })).refused, "not_recognised");
	assert.equal(readFake(EA("KeePassFile", { Protected: "True" })).refused, "protected_values");
});

test("xml: entries are read from the strings of every Entry directly inside a Group; everything else is passed over", () => {
	const { parsed } = readFake(E("KeePassFile",
		E("Meta", E("Generator", "KeePassXC"), E("RecycleBinUUID", " BIN== "), E("RecycleBinUUID", "ROOT==")),
		E("Root",
			E("Group", E("UUID", "ROOT=="), E("Name", "Database"),
				E("Entry", S("Title", " Example "), S("UserName", " fake.user "), S("Password", "   "), S("URL", "example.com"), S("Notes", "line one\nline two"),
					S("otp", "otpauth://totp/x?secret=FAKE"), S(" Custom ", " value "), S("Empty", ""), E("String", E("Value", "no key")), E("String", E("Key", "NoValue")),
					E("History", E("Entry", S("Title", "an earlier version"))), E("Times", E("Expires", "False")), COMMENT("c")),
				E("Group", E("Name", " Internet "), E("UUID", "G1=="), E("Name", "second name"), E("UUID", "BIN=="),
					E("Entry", E("String", E("Key", "Ti", CDATA("tle")), E("Value", "pre", COMMENT("x"), CDATA(" <cdata> "), E("b", "inner"), "post")), S("title", "lower case key")),
					E("Group", E("Name", ""), E("Group", E("Name", "Deep"), E("Entry", S("Title", "deep one"))))),
				E("Group", E("UUID", " BIN==\n"), E("Name", "Recycle Bin"), E("Entry", S("Title", "deleted")), E("Group", E("Name", "In the bin"), E("Entry", S("Title", "deleted too")))),
				E("Unknown", E("Entry", S("Title", "not directly inside a group")))),
			E("Entry", S("Title", "directly inside Root")),
			E("DeletedObjects")),
		E("Root", E("Group", E("Entry", S("Title", "a second Root is passed over")))),
		E("Meta", E("RecycleBinUUID", "G1=="))));
	assert.equal(parsed.format, "keepass_xml");
	assert.equal(parsed.label, "KeePass 2 (XML)");
	assert.equal(parsed.records, 5);
	assert.equal(parsed.inTrash, 2);
	assert.deepEqual(parsed.unsupported, {});
	assert.deepEqual(parsed.ignoredColumns, []);
	assert.deepEqual(parsed.entries, [
		{ position: 1, name: " Example ", username: " fake.user ", password: "   ", notes: "line one\nline two", favorite: false, addresses: ["example.com"], totp: "", folder: "",
			customFields: [{ name: "otp", value: "otpauth://totp/x?secret=FAKE" }, { name: "Custom", value: " value " }, { name: "Empty", value: "" }, { name: "NoValue", value: "" }], problem: null },
		{ position: 2, name: "pre <cdata> post", username: "", password: "", notes: "", favorite: false, addresses: [], totp: "", folder: "Internet",
			customFields: [{ name: "title", value: "lower case key" }], problem: null },
		{ position: 3, name: "deep one", username: "", password: "", notes: "", favorite: false, addresses: [], totp: "", folder: "Internet/Deep", customFields: [], problem: null }
	]);
});

test("xml: a standard field more than once marks the entry, keeps the first value, and a custom field may repeat", () => {
	const { parsed } = readFake(E("KeePassFile", E("Root", E("Group",
		E("Entry", S("Title", "first"), S("Title", "second"), S("x", "1"), S("x", "2")),
		E("Entry", S("Password", "a"), S("UserName", "u"), S("Password", "")),
		E("Entry", S("URL", ""), S("URL", "https://example.com")),
		E("Entry", S("Notes", "n"), E("String", E("Key", "Notes"), E("Key", "Title"), E("Value", "v"), E("Value", "w")))))));
	assert.deepEqual(parsed.entries.map((e) => [e.name, e.password, e.addresses, e.notes, e.problem, e.customFields.length]), [
		["first", "", [], "", "field_twice", 2], ["", "a", [], "", "field_twice", 0], ["", "", [], "", "field_twice", 0], ["", "", [], "n", "field_twice", 0]
	]);
});

test("xml: the recycle bin is the group the file names, unless it names none", () => {
	const tree = (bin) => E("KeePassFile", E("Root", E("Group", E("UUID", "ROOT"), E("Entry", S("Title", "kept")), E("Group", E("UUID", "BIN"), E("Entry", S("Title", "binned"))))), E("Meta", bin === null ? E("x") : E("RecycleBinUUID", bin)));
	assert.equal(readFake(tree("BIN")).parsed.inTrash, 1);        // Meta may come after Root
	assert.equal(readFake(tree(" BIN\n")).parsed.inTrash, 1);
	assert.equal(readFake(tree("ROOT")).parsed.inTrash, 2);
	for (const none of [null, "", "  ", "AAAAAAAAAAAAAAAAAAAAAA==", "bin", "OTHER"]) { assert.equal(readFake(tree(none)).parsed.inTrash, 0, String(none)); }
	// All entries count towards the records, those in the bin too.
	assert.equal(readFake(tree("BIN")).parsed.records, 2);
	assert.deepEqual(readFake(tree("BIN")).parsed.entries.map((e) => e.position), [1]);
});

test("xml: the first fault in the order of the document decides", () => {
	const deep = (levels, innermost) => { let node = innermost || E("a"); for (let i = 1; i < levels; i++) { node = E("a", node); } return node; };
	const groups = (levels, innermost) => { let node = E("Group", innermost || E("Name", "g")); for (let i = 1; i < levels; i++) { node = E("Group", node); } return node; };
	// The root is the first level: 100 levels are read, the 101st is refused — also where nothing is read.
	assert.equal(readFake(E("KeePassFile", E("Meta", deep(98)))).parsed.records, 0);
	assert.equal(readFake(E("KeePassFile", E("Meta", deep(99)))).refused, "nested_too_deeply");
	assert.equal(readFake(E("KeePassFile", E("Unknown", deep(99)))).refused, "nested_too_deeply");
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", E("String", E("Value", deep(94)))))))).parsed.records, 1);
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", E("String", E("Value", deep(95)))))))).refused, "nested_too_deeply");
	// Groups: 64 inside one another, the one directly inside Root being the first.
	assert.equal(readFake(E("KeePassFile", E("Root", groups(64, E("Entry", S("Title", "deep")))))).parsed.records, 1);
	assert.equal(readFake(E("KeePassFile", E("Root", groups(65)))).refused, "nested_too_deeply");
	// A protected value anywhere, read or passed over; the mark is 1, or true in any letter case.
	for (const mark of ["True", "true", "TRUE", "tRuE", "1"]) {
		assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", S("Password", "AAAA", { Protected: mark })))))).refused, "protected_values", mark);
		assert.equal(readFake(E("KeePassFile", E("Meta", E("Binaries", EA("Binary", { ID: "0", Protected: mark }, "AAAA"))))).refused, "protected_values", mark);
		assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", E("History", E("Entry", S("Password", "AAAA", { Protected: mark })))))))).refused, "protected_values", mark);
	}
	for (const mark of ["False", "0", "", " True", "True ", "yes", "01", "true\u212A", "T\u0280UE"]) {
		assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", S("Password", "x", { Protected: mark })))))).parsed.records, 1, JSON.stringify(mark));
	}
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", S("Password", "x", { ProtectInMemory: "True", protected: "True" })))))).parsed.records, 1);
	// Which comes first in the document decides between two faults ...
	assert.equal(readFake(E("KeePassFile", E("Meta", EA("x", { Protected: "True" })), E("Root", groups(65)))).refused, "protected_values");
	assert.equal(readFake(E("KeePassFile", E("Root", groups(65)), E("Meta", EA("x", { Protected: "True" })))).refused, "nested_too_deeply");
	// ... and on one element the depth is asked before the mark, and the mark before what the element is.
	assert.equal(readFake(E("KeePassFile", E("Meta", deep(98, EA("a", { Protected: "True" }))))).refused, "protected_values");
	assert.equal(readFake(E("KeePassFile", E("Meta", deep(99, EA("a", { Protected: "True" }))))).refused, "nested_too_deeply");
	assert.equal(readFake(E("KeePassFile", E("Root", groups(64, EA("Group", { Protected: "True" }))))).refused, "protected_values");
});

test("xml: the 10,001st entry refuses the file, entries in the recycle bin and entries with nothing in them included", () => {
	const entries = (n) => { const list = []; for (let i = 0; i < n; i++) { list.push(E("Entry")); } return list; };
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", ...entries(10000))))).parsed.records, 10000);
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", ...entries(5000)), E("Group", ...entries(5001))))).refused, "too_many_entries");
	// Entries of a History do not count.
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", E("Entry", E("History", ...entries(10001))))))).parsed.records, 1);
	// The entry that is one too many is met before a protected value that follows it.
	assert.equal(readFake(E("KeePassFile", E("Root", E("Group", ...entries(10001), EA("x", { Protected: "True" }))))).refused, "too_many_entries");
});

// ------------------------------------------------------------------ addresses (§7.2, §7.3)
test("addresses: with the scheme http or https it is a web address, whatever follows; any other scheme is not", () => {
	for (const v of ["https://example.com", "http://example.com/login?next=%2F#top", "HTTPS://EXAMPLE.COM/Path", "hTtP://intranet", "https://user:secret@example.com:8443/", "https://[::1]:8080/", "http://", "https://not a host"]) {
		assert.equal(ie._classifyAddress(v), "web", v);
	}
	for (const v of ["android://Hash==@com.example.app/", "androidapp://com.example.app", "ftp://files.example.com/", "chrome://FirefoxAccounts", "file:///home/user/secrets.txt",
		"ssh://git@example.com/repo.git", "custom+scheme.v2-x://thing", "httpss://example.com", "example.com://what", "h\u0167tp://example.com", "\uFF48ttp://example.com"]) {
		assert.equal(ie._classifyAddress(v), "other", v);
	}
});

test("addresses: without a scheme, what looks like a host is given https://, and what does not is not an address BitosX stores", () => {
	for (const v of ["example.com", "www.example.com", "example.com:8443/path", "example.com/login", "example.com?x=1", "example.com#top", "sub.domain.example.co.uk/a b?c=d#e", "EXAMPLE.COM",
		"my-site.example", "a.b", "1password.com", "example.xn--p1ai", "xn--bcher-kva.de", "192.168.1.1", "192.168.1.1:8080", "10.0.0.1/admin", "255.255.255.255", "0.0.0.0", "example.com:1",
		"example.com:65535", "example.com:99999", "example.com/a\u2028b\u2029c\u0085d", "example.com/\u65E5\u672C \uD83D\uDE00"]) {
		assert.equal(ie._classifyAddress(v), "host", v);
		assert.equal(ie._looksLikeHost(v), true, v);
	}
	for (const v of ["localhost", "localhost:3000", "intranet", "My bank", "n/a", "user@example.com", "user:secret@example.com", "mailto:user@example.com", "javascript:alert(1)", "data:text/html,x",
		"about:blank", "http:example.com", "//example.com/path", "/just/a/path", "C:\\Users\\me\\file", "v1.2", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.", "example.com.", ".example.com",
		"example..com", "-example.com", "example-.com", "exa_mple.com", "example.c0m-", "example.123", "example.com:", "example.com:port", "example.com:123456", "example.com:80x", "example.com:80:90",
		"example.com path", "example .com", "[::1]", "::1", "b\u00FCcher.de", "r\u00E4ksm\u00F6rg\u00E5s.se", "\u4F8B\u3048.jp", ""]) {
		assert.equal(ie._classifyAddress(v), "other", v);
	}
	for (const host of ["b\u00FCcher.de", "\u4F8B\u3048.jp"]) { assert.equal(ie._classifyAddress("https://" + host), "web"); }
	for (const v of ["https://example.com/a\tb", "https://exam\tple.com", "example.com/\u0000", "example.com\u007F", "\u0001https://example.com"]) {
		assert.equal(ie._classifyAddress(v), "other", JSON.stringify(v));
	}
});

test("addresses: the hand-written rules agree with the patterns of the specification", () => {
	const hostPattern = /^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?|(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})(?::[0-9]{1,5})?(?:[/?#][\s\S]*)?$/;
	const schemePattern = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;
	// Every string of up to four of these characters: some 70,000 values.
	const alphabet = ["a", "Z", "0", "9", "2", "5", ".", "-", ":", "/", "?", "#", "@", "_", " ", "+"];
	const values = [""];
	let frontier = [""];
	for (let length = 1; length <= 4; length++) {
		const next = [];
		for (const prefix of frontier) { for (const c of alphabet) { next.push(prefix + c); } }
		values.push(...next);
		frontier = next;
	}
	// Longer ones, put together the way real values are: parts of a name with dots between them,
	// then perhaps a port, then perhaps a path. Many are hosts, many are almost hosts.
	const labels = ["a", "ab", "a-b", "a--b", "example", "com", "Co", "x1", "1x", "9", "0", "1", "25", "99", "100", "199", "249", "250", "255", "256", "01", "001", "1234", "-a", "a-", "-", "a_b", "", "xn--p1ai", "A0-z"];
	const ports = ["", "", "", ":", ":8", ":80", ":8443", ":65535", ":99999", ":123456", ":8x", ":x", ":80:81"];
	const tails = ["", "", "", "/", "/path", "?q=1", "#top", "/a b", " ", "x", "@host", "://x", "/a:b@c", "/a\nb", "\n"];
	const fronts = ["", "", "", "", "", "", "http", "https", "ftp", "a+b.c-d", "1a", "+a", " "];
	const random = seeded(20261110);
	const pick = (list) => list[Math.floor(random() * list.length)];
	for (let i = 0; i < 250000; i++) {
		let value = pick(fronts);
		if (value.length > 0 && random() < 0.5) { value += "://"; }
		for (let j = 0, count = 1 + Math.floor(random() * 5); j < count; j++) { value += (j > 0 ? "." : "") + pick(labels); }
		values.push(value + pick(ports) + pick(tails));
	}
	let hosts = 0, schemes = 0;
	for (const value of values) {
		const expectedHost = hostPattern.test(value);
		if (ie._looksLikeHost(value) !== expectedHost) { assert.fail("host: " + JSON.stringify(value)); }
		const scheme = schemePattern.exec(value);
		const kind = ie._classifyAddress(value);
		const expectedKind = /[\u0000-\u001F\u007F]/.test(value) ? "other" : scheme ? (/^https?$/i.test(scheme[1]) ? "web" : "other") : expectedHost ? "host" : "other";
		if (kind !== expectedKind) { assert.fail("kind: " + JSON.stringify(value)); }
		hosts += expectedHost ? 1 : 0;
		schemes += scheme ? 1 : 0;
	}
	// The comparison saw plenty of both answers to both questions.
	assert.ok(hosts > 10000, `${hosts} hosts`);
	assert.ok(values.length - hosts > 100000, `${values.length - hosts} that are not hosts`);
	assert.ok(schemes > 10000, `${schemes} schemes`);
});

test("addresses: the host of a web address is taken from its text", () => {
	const cases = [
		["https://example.com", "example.com"], ["https://EXAMPLE.com/Path", "example.com"], ["http://www.example.com:8080/login?x=1#y", "www.example.com"],
		["https://user:secret@example.com:8443/", "example.com"], ["https://a@b@example.com/", "example.com"], ["https://example.com?next=/a/b", "example.com"],
		["https://example.com#frag", "example.com"], ["https://192.168.1.1:8080/admin", "192.168.1.1"], ["https://[2001:DB8::1]:8443/x", "[2001:db8::1]"],
		["https://[::1]", "[::1]"], ["https://[::1", "[::1"], ["https://example.com:/x", "example.com"], ["https://intranet", "intranet"], ["https://B\u00DCCHER.de/", "b\u00DCcher.de"],
		["https://xn--bcher-kva.de/", "xn--bcher-kva.de"], ["https:///path", ""], ["https://", ""], ["https://@/", ""], ["https://example.com:abc/x", "example.com:abc"],
		["https://a:b:80/", "a:b"], ["HTTPS://Shop.Example:8443/x", "shop.example"], ["https://example.com\\path", "example.com\\path"], ["no scheme", ""]
	];
	for (const [address, host] of cases) { assert.equal(ie._hostOf(address), host, address); }
});

test("addresses: the host rule both clients share (§7.3)", () => {
	const plausible = ["https://example.com", "http://example.com:8080/login?next=%2F", "https://user:secret@example.com:8443/p?q#f", "https://a:b:c@example.com/", "https://example.com@other.example/",
		"https://intranet", "http://localhost:3000", "https://my_host.example.com/", "https://_dmarc.example.com/", "https://-a.example/", "https://example.com.", "https://example.com./path",
		"https://example.com:", "https://example.com:0", "https://example.com:99999", "https://192.168.1.1", "https://192.168.1.1:8080/admin", "https://1.2.3.4.", "https://1e3.example", "https://[::1]",
		"https://[::1]:8080/", "https://[2001:DB8::1]:", "https://[::ffff:1.2.3.4]/", "https://xn--bcher-kva.example/", "HTTPS://EXAMPLE.COM/Path", "https://example.com/a b?c d#e f",
		"https://example.com/back\\slash\\in\\the\\path", "https://example.com/%zz{x}|y^z`<>\"'", "https://b\u00FCcher.example/", "https://\u65E5\u672C\u8A9E.example/", "https://example.\u65E5\u672C/",
		"https://0x.example/", "https://a.0xg/", "https://09a.example/"];
	for (const a of plausible) { assert.equal(ie._hasPlausibleHost(a), true, a); }
	const implausible = ["https://", "http://", "https:///path", "https://@/", "https://user@", "https://:8080", "https://user:p@ss@example.com", "https://a@b@c/", "https://a..b", "https://.example.com",
		"https://example..com", "https://.", "https://..", "https://example.com..", "https://exa mple.com/", "https://exa!mple.com", "https://exa\"mple.com", "https://exa'mple.com", "https://*.example.com",
		"https://%41.com", "https://ex%61mple.com/", "https://example.com\\path", "https://exam[ple.com", "https://example.com:abc", "https://example.com:80:90", "https://example.com:80a/",
		"https://example.123", "https://v1.2", "https://1.2.3", "https://1", "https://1.2.3.4.5", "https://256.1.1.1", "https://1.2.3.256", "https://01.02.03.04", "https://0x7f.1", "https://0x7f000001",
		"https://0x.1.1.1", "https://2130706433", "https://1.2.3.4..", "https://[::1", "https://[]/", "https://[zz]/", "https://[fe80::1%25eth0]/", "https://[::1]x", "https://[::1]:80a",
		"not an address at all", "https://a.0x/", "https://a.0X1F/", "https://a.09/"];
	for (const a of implausible) { assert.equal(ie._hasPlausibleHost(a), false, a); }
});

test("addresses: a very long value is told apart in one pass", () => {
	const started = Date.now();
	assert.equal(ie._classifyAddress("a-b.".repeat(2000000) + "c_"), "other");
	assert.equal(ie._classifyAddress("a-b.".repeat(2000000) + "com"), "host");
	assert.equal(ie._classifyAddress("a".repeat(8000000)), "other");
	assert.equal(ie._classifyAddress("a".repeat(8000000) + "://x"), "other");
	assert.equal(ie._hasPlausibleHost("https://" + "a.".repeat(4000000) + "9"), false);
	assert.equal(ie._hasPlausibleHost("https://" + "a.".repeat(4000000) + "com"), true);
	assert.equal(ie._hasPlausibleHost("https://" + "@".repeat(8000000)), false);
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test("addresses: each of the 151 values of addresses.csv becomes what the desktop makes of it", () => {
	const expected = conformance.readExpected("addresses.csv.expected.json").cases[0].result;
	const rows = [];
	const reader = new ie._CsvRecordReader(text(fs.readFileSync(path.join(conformance.DIRECTORY, "addresses.csv"))));
	for (let r = reader.readRecord(); r !== null; r = reader.readRecord()) { rows.push(r); }
	assert.deepEqual(rows.shift(), ["name", "url", "password"]);
	assert.equal(rows.length, 151);
	assert.equal(expected.candidates.length, 151);
	const kinds = { web: 0, host: 0, other: 0, invalid: 0 };
	rows.forEach((row, i) => {
		const want = expected.candidates[i];
		const got = ie._normalizeEntry({ position: i + 1, name: row[0], username: "", password: row[2], notes: "", favorite: false, addresses: [row[1]], totp: "", folder: "", customFields: [], problem: null }, false);
		const what = `row ${i + 1}: ${JSON.stringify(row[1])}`;
		assert.deepEqual(got.urls, want.urls, what);
		assert.deepEqual(got.extras.otherAddresses, want.extras.otherAddresses, what);
		assert.equal(got.httpsAdded, want.httpsAdded, what);
		assert.equal(got.reason, want.reason, what);
		// And the pieces say why: an address is a web address, a host, or neither; a web address
		// is refused where the shared host rule or the vault's own rule refuses it.
		ie._splitLines(row[1]).map(ie._trim).filter((a) => a.length > 0).forEach((address) => {
			const kind = ie._classifyAddress(address);
			kinds[kind]++;
			if (kind !== "other") {
				const url = kind === "host" ? "https://" + address : address;
				const valid = url.length <= vc.LIMITS.url && ie._hasPlausibleHost(url) && vc.isValidUrl(url);
				if (!valid) { kinds.invalid++; }
				if (want.urls.length === 1) { assert.equal(valid, want.reason === null, what); }
			}
		});
	});
	assert.ok(kinds.web > 50 && kinds.host > 5 && kinds.other > 10 && kinds.invalid > 30, JSON.stringify(kinds));
});

// --------------------------------------------------------- from an entry to an item (§7)
const csv = (rows, header) => (header || "name,url,username,password,note") + "\n" + rows.join("\n") + "\n";

test("an item: the name is trimmed, and username, password and notes are taken exactly as they are", () => {
	const c = only(candidates(csv(["\" \u00A0Example\u0085 \",https://example.com/,\"  fake user  \",\"  FAKE pw  \",\" notes \n\""])));
	assert.deepEqual([c.name, c.username, c.password, c.notes, c.nameWasDerived, c.status, c.reason], ["Example", "  fake user  ", "  FAKE pw  ", " notes \n", false, "add", null]);
});

test("an item: an address value is split into lines, each trimmed; web addresses, hosts given https://, and other addresses", () => {
	const c = only(candidates(csv(["n,\" https://a.example/ \r\nb.example:8443/x\rftp://c.example\n\n  \nMy bank\nandroid://x@y\nhttps://a.example/\",u,p,"])));
	assert.deepEqual(c.urls, ["https://a.example/", "https://b.example:8443/x", "https://a.example/"]);
	assert.equal(c.httpsAdded, 1);
	assert.deepEqual(c.extras.otherAddresses, ["ftp://c.example", "My bank", "android://x@y"]);
});

test("an item: an entry with nothing in it is counted and passed over; a folder alone does not make an entry", () => {
	const header = "name,url,username,password,note,totp,group,fields";
	const p = plan(csv([",,,,,,Folder only,", "\" \",\"\n \n\",\"\u00A0\",\"\t\",\" \r\n \",\" \",\" \",\"k: \n\nx: \u2003\"", ",,,,,,,k: v", ",,,,,x,,", ",ftp://x,,,,,,", ",,,,.,,,"], header));
	assert.equal(p.records, 6);
	assert.equal(p.counts.empty, 2);
	assert.deepEqual(p.candidates.map((c) => [c.position, c.name, c.nameWasDerived]), [[3, "Untitled", true], [4, "Untitled", true], [5, "Untitled", true], [6, "Untitled", true]]);
});

test("an item: a missing name is the host of the first web address, else the username, else Untitled — the first that is 1 to 200 long", () => {
	const derived = (row, header) => { const c = only(candidates(csv([row], header))); assert.equal(c.nameWasDerived, true); return c.name; };
	assert.equal(derived(",https://Shop.Example:8443/x,user,p,"), "shop.example");
	assert.equal(derived(",\"ftp://first.example\nsecond.example/path\nhttps://third.example\",user,p,"), "second.example");
	assert.equal(derived(",https://user:pw@EXAMPLE.org/,user,p,"), "example.org");
	assert.equal(derived(",https://[2001:DB8::1]:443/,user,p,"), "[2001:db8::1]");
	assert.equal(derived(",https://B\u00DCCHER.example/,user,p,"), "b\u00DCcher.example");
	assert.equal(derived(",https://xn--bcher-kva.example/,user,p,"), "xn--bcher-kva.example");
	assert.equal(derived(",https:///no-host,\" fake.user\u00A0\",p,"), "fake.user");
	assert.equal(derived(",https://" + "h".repeat(200) + "/,user,p,"), "h".repeat(200));
	assert.equal(derived(",https://" + "h".repeat(201) + "/,user,p,"), "user");
	assert.equal(derived(",https://" + "h".repeat(201) + "/," + "u".repeat(201) + ",p,"), "Untitled");
	assert.equal(derived(",android://x,,p,"), "Untitled");
	assert.equal(derived(",,,p,"), "Untitled");
	// A derived name never makes an entry fail, and a name the file gives is never replaced, even if it is too long.
	assert.equal(only(candidates(csv([",https://" + "h".repeat(201) + "/,,p,"]))).reason, null);
	const long = only(candidates(csv(["n".repeat(201) + ",https://example.com/,user,p,"])));
	assert.deepEqual([long.name.length, long.nameWasDerived, long.reason, long.status], [201, false, "name_too_long", "not_imported"]);
});

test("an item: the limits are the vault's own, counted in UTF-16 code units, and the first that is broken is the reason", () => {
	const reason = (row, header, options) => only(candidates(csv([row], header), [], options)).reason;
	const key = "\uD83D\uDD11";   // one character, two code units
	assert.equal(reason("n".repeat(200) + ",,,p,"), null);
	assert.equal(reason(key.repeat(100) + ",,,p,"), null);
	assert.equal(reason(key.repeat(100) + "n,,,p,"), "name_too_long");
	assert.equal(reason("n,," + "u".repeat(320) + ",p,"), null);
	assert.equal(reason("n,," + "u".repeat(321) + ",p,"), "username_too_long");
	assert.equal(reason("n,,," + "p".repeat(4096) + ","), null);
	assert.equal(reason("n,,," + "p".repeat(4097) + ","), "password_too_long");
	assert.equal(reason("n,,,p," + "x".repeat(16384)), null);
	assert.equal(reason("n,,,p," + "x".repeat(16385)), "notes_too_long");
	const urls = (n) => "\"" + Array(n).fill("https://example.com/").join("\n") + "\"";
	assert.equal(reason("n," + urls(64) + ",,p,"), null);
	assert.equal(reason("n," + urls(65) + ",,p,"), "too_many_urls");
	// Only web addresses count towards the 64.
	assert.equal(reason("n,\"" + Array(64).fill("https://example.com/").concat(Array(10).fill("ftp://x")).join("\n") + "\",,p,"), null);
	assert.equal(reason("n,https://example.com/" + "a".repeat(2048 - 20) + ",,p,"), null);
	assert.equal(reason("n,https://example.com/" + "a".repeat(2049 - 20) + ",,p,"), "url_too_long");
	// With https://, if it was put in front.
	assert.equal(reason("n,example.com/" + "a".repeat(2048 - 20) + ",,p,"), null);
	assert.equal(reason("n,example.com/" + "a".repeat(2049 - 20) + ",,p,"), "url_too_long");
	assert.equal(reason("n,https://a..b,,p,"), "url_invalid");
	assert.equal(reason("n,https://example.com:99999,,p,"), "url_invalid");   // passes the shared rule, fails the vault's own
	// The order: a row whose values moved, then name, username, password, notes, how many addresses, how long, whether valid.
	const all = ["n".repeat(201), "\"" + Array(65).fill("https://a..b/" + "x".repeat(2049)).join("\n") + "\"", "u".repeat(321), "p".repeat(4097), "x".repeat(16385)];
	const steps = ["row_has_extra_values", "name_too_long", "username_too_long", "password_too_long", "notes_too_long", "too_many_urls", "url_too_long", "url_invalid", null];
	const fix = [() => {}, () => { all[0] = "n"; }, () => { all[2] = "u"; }, () => { all[3] = "p"; }, () => { all[4] = "x"; },
		() => { all[1] = "\"https://example.com/\nhttps://a..b/" + "x".repeat(2049) + "\""; }, () => { all[1] = "\"https://example.com/\nhttps://a..b/\""; }, () => { all[1] = "https://example.com/"; }];
	let extra = ",moved";
	steps.forEach((step, i) => {
		assert.equal(reason(all.join(",") + extra), step, "step " + i);
		if (i === 0) { extra = ""; } else if (fix[i]) { fix[i](); }
	});
});

test("an item: extras are counted, left out by default, and copied into the notes as labelled lines when asked", () => {
	const header = "name,url,username,password,notes,totp,folder,fields";
	const row = "n,\"https://example.com/\nandroid://app\nMy bank\",u,p,own notes, FAKESECRET , Work/Mail ,\"PIN: 0000\nno name\nEmpty: \nSeveral: a: b\"";
	const left = only(candidates(csv([row], header)));
	assert.equal(left.notes, "own notes");
	assert.deepEqual(left.extras, { totp: "FAKESECRET", folder: "Work/Mail", otherAddresses: ["android://app", "My bank"],
		customFields: [{ name: "PIN", value: "0000" }, { name: "", value: "no name" }, { name: "Several: a", value: "b" }] });
	const copied = only(candidates(csv([row], header), [], { copyExtrasToNotes: true }));
	assert.equal(copied.notes, "own notes\n\nAuthenticator key (TOTP): FAKESECRET\nFolder: Work/Mail\nOther address: android://app\nOther address: My bank\nPIN: 0000\nField: no name\nSeveral: a: b");
	assert.deepEqual(copied.extras, left.extras);
	// Without notes of its own the lines are the notes; with no extras the notes are unchanged.
	assert.equal(only(candidates(csv(["n,,u,p,,,F,"], header), [], { copyExtrasToNotes: true })).notes, "Folder: F");
	assert.equal(only(candidates(csv(["n,,u,p,\" kept as it is \",,,"], header), [], { copyExtrasToNotes: true })).notes, " kept as it is ");
	// A value of several lines is written as it is.
	assert.equal(only(candidates("{\"items\": [{\"type\": 1, \"name\": \"n\", \"fields\": [{\"name\": \"k\", \"value\": \"one\\r\\ntwo\"}]}]}", [], { copyExtrasToNotes: true })).notes, "k: one\r\ntwo");
});

test("an item: notes that only pass the limit with the extras copied in are a reason of their own", () => {
	const header = "name,password,notes,totp";
	const fits = "x".repeat(16384 - "\n\nAuthenticator key (TOTP): S".length);
	assert.equal(only(candidates(csv(["n,p," + fits + ",S"], header), [], { copyExtrasToNotes: true })).reason, null);
	const c = only(candidates(csv(["n,p," + fits + "x,S"], header), [], { copyExtrasToNotes: true }));
	assert.deepEqual([c.reason, c.status, c.notes.length], ["notes_too_long_with_extras", "not_imported", 16385]);
	assert.equal(only(candidates(csv(["n,p," + fits + "x,S"], header))).reason, null);
	// Notes that are too long by themselves are that, with or without the extras; another reason comes first.
	assert.equal(only(candidates(csv(["n,p," + "x".repeat(16385) + ",S"], header), [], { copyExtrasToNotes: true })).reason, "notes_too_long");
	assert.equal(only(candidates(csv(["n," + "p".repeat(4097) + "," + fits + "x,S"], header), [], { copyExtrasToNotes: true })).reason, "password_too_long");
});

// ------------------------------------------------------------- duplicates and the plan (§8, §9)
test("duplicates: the same name, username, password and web addresses in the same order — in the vault, or earlier in the file", () => {
	const vault = [{ name: "Example", username: "fake.user", password: "FAKE-pw", urls: ["https://example.com/", "https://example.org/"] }];
	const rows = [
		"Example,\"https://example.com/\nhttps://example.org/\",fake.user,FAKE-pw,other notes",     // the vault's item
		"Example,\"https://example.org/\nhttps://example.com/\",fake.user,FAKE-pw,",                // another order
		"Example,https://example.com/,fake.user,FAKE-pw,",                                          // one address fewer
		"example,\"https://example.com/\nhttps://example.org/\",fake.user,FAKE-pw,",                // another name
		"Example,\"https://example.com/\nhttps://example.org/\",fake.user ,FAKE-pw,",               // another username (a space)
		"Example,\"https://example.com/\nhttps://example.org/\",fake.user,FAKE-PW,",                // another password
		"Example,https://example.com/,fake.user,FAKE-pw,the third row again",                       // an earlier entry of the file
		"\" Example \",\" https://example.com/ \nexample.org/\",fake.user,FAKE-pw,",                // as it would be stored: trimmed, https:// added
		"Example,\"https://example.com/\nhttp://example.org/\",fake.user,FAKE-pw,"                  // another scheme
	];
	const p = plan(csv(rows), vault);
	assert.deepEqual(p.candidates.map((c) => [c.status, c.duplicate]), [["duplicate", true], ["add", false], ["add", false], ["add", false], ["add", false], ["add", false], ["duplicate", true], ["duplicate", true], ["add", false]]);
	assert.deepEqual([p.counts.toAdd, p.counts.duplicates, p.counts.vaultItemsBefore, p.counts.vaultItemsAfter], [6, 3, 1, 7]);
	// The comparison is of what would be stored: the name trimmed, and https:// in front of the host.
	assert.deepEqual(p.candidates[7].urls, ["https://example.com/", "https://example.org/"]);
	assert.equal(p.candidates[7].httpsAdded, 1);
});

test("duplicates: a value the vault does not have equals an empty one; its names and addresses are trimmed for the comparison", () => {
	const vault = [
		{ name: " Only a name\u0085", username: null, password: null, urls: [] },
		{ name: "Spaced", username: " u ", password: " p ", urls: [" https://example.com/ ", "\u00A0https://example.org/"] },
		{ name: "Undefined", urls: [] }
	];
	const p = plan(csv(["Only a name,,,,", "Spaced,\"https://example.com/\nhttps://example.org/\", u , p ,", "Spaced,\"https://example.com/\nhttps://example.org/\",u,p,", "Undefined,,,,"]), vault);
	assert.deepEqual(p.candidates.map((c) => c.status), ["duplicate", "duplicate", "add", "duplicate"]);
	// Nothing is folded or normalised: a composed and a decomposed letter are two names.
	const nfc = plan(csv(["Caf\u00E9,,,p,", "Cafe\u0301,,,p,"]), [{ name: "Caf\u00E9", username: "", password: "p", urls: [] }]);
	assert.deepEqual(nfc.candidates.map((c) => c.status), ["duplicate", "add"]);
});

test("duplicates: the four values cannot be confused with one another, whatever they hold", () => {
	const vault = [{ name: "a", username: "b:c", password: "", urls: [] }, { name: "x", username: "", password: "", urls: ["https://example.com/1:", "https://example.org/"] }];
	const p = plan(csv(["a:b,,c,,", "a,,b,c,", "\"a1:b\",,,,", "x,\"https://example.com/\nhttps://example.org/\",,,", "x,https://example.com/1:https://example.org/,,,"]), vault);
	assert.deepEqual(p.candidates.map((c) => c.duplicate), [false, false, false, false, false]);
});

test("duplicates: an entry that is not imported is nobody's duplicate, and nothing is a duplicate of it", () => {
	const long = "p".repeat(4097);
	const p = plan(csv(["Example,,u," + long + ",", "Example,,u," + long + ",", "Example,,u,FAKE-pw,", "Example,,u,FAKE-pw,", "Example,,u,FAKE-pw,moved,values"]), [{ name: "Example", username: "u", password: long, urls: [] }]);
	assert.deepEqual(p.candidates.map((c) => [c.status, c.duplicate, c.reason]), [
		["not_imported", false, "password_too_long"], ["not_imported", false, "password_too_long"], ["add", false, null], ["duplicate", true, null], ["not_imported", false, "row_has_extra_values"]
	]);
	assert.deepEqual([p.counts.toAdd, p.counts.duplicates, p.counts.notImported], [1, 1, 3]);
});

test("duplicates: with 'Import duplicates too' they are added like any other entry, and still counted as duplicates", () => {
	const input = csv(["Example,,u,FAKE-pw,", "Example,,u,FAKE-pw,", "Example,,u,FAKE-pw,"]);
	const vault = [{ name: "Example", username: "u", password: "FAKE-pw", urls: [] }];
	const skipped = plan(input, vault);
	assert.deepEqual(skipped.candidates.map((c) => [c.status, c.duplicate]), [["duplicate", true], ["duplicate", true], ["duplicate", true]]);
	assert.deepEqual([skipped.counts.toAdd, skipped.counts.duplicates, skipped.counts.vaultItemsAfter], [0, 3, 1]);
	const imported = plan(input, vault, { importDuplicates: true });
	assert.deepEqual(imported.candidates.map((c) => [c.status, c.duplicate]), [["add", true], ["add", true], ["add", true]]);
	assert.deepEqual([imported.counts.toAdd, imported.counts.duplicates, imported.counts.vaultItemsAfter], [3, 3, 4]);
});

test("the plan: extras, added https:// and derived names are counted over the entries that will be added only", () => {
	const header = "name,url,username,password,notes,totp,folder,fields";
	const rows = [
		",\"a.example\nb.example\nftp://x\",u,p,,S,F,k: v",         // added: 2 hosts, a derived name, one of every extra
		",\"a.example\nb.example\nftp://x\",u,p,,S,F,k: v",         // a duplicate of it: counted nowhere
		"n," + "p".repeat(10) + ".example,u," + "p".repeat(4097) + ",,S,F,k: v",   // not imported: counted nowhere
		"other,c.example,u,p,,,,\"a: 1\nb: 2\""
	];
	const p = plan(csv(rows, header));
	assert.deepEqual(p.counts, { toAdd: 2, duplicates: 1, notImported: 1, empty: 0, httpsAdded: 3, namesDerived: 1, vaultItemsBefore: 0, vaultItemsAfter: 2, exceedsVaultItemLimit: false });
	assert.deepEqual(Object.entries(p.extras), [["totp", 1], ["folder", 1], ["other_address", 1], ["custom_field", 3]]);
	// With the duplicates imported too, theirs count as well.
	const all = plan(csv(rows, header), [], { importDuplicates: true });
	assert.deepEqual([all.counts.toAdd, all.counts.httpsAdded, all.counts.namesDerived], [3, 5, 2]);
	assert.deepEqual(all.extras, { totp: 2, folder: 2, other_address: 2, custom_field: 4 });
	// A kind with none is absent.
	assert.deepEqual(plan(csv(["n,,u,p,,,F,"], header)).extras, { folder: 1 });
	assert.deepEqual(plan(csv(["n,,u,p,,,,"], header)).extras, {});
});

test("the plan: both choices are off unless chosen, and planning changes neither the file's entries nor the vault", () => {
	const parsed = parse(csv(["n,example.com,u,p,note,S"], "name,url,username,password,note,totp"));
	const vault = Object.freeze([Object.freeze({ name: " n ", username: "u", password: "p", urls: Object.freeze([" https://example.com "]) })]);
	const before = JSON.stringify(parsed);
	for (const options of [undefined, null, {}, { copyExtrasToNotes: undefined }, { copyExtrasToNotes: 0, importDuplicates: "" }]) {
		const p = ie.planImport(parsed, vault, options);
		assert.deepEqual(p.options, { copyExtrasToNotes: false, importDuplicates: false });
		assert.equal(only(p.candidates).notes, "note");
		assert.equal(only(p.candidates).status, "duplicate");
	}
	const chosen = ie.planImport(parsed, vault, { copyExtrasToNotes: true, importDuplicates: true });
	assert.deepEqual(chosen.options, { copyExtrasToNotes: true, importDuplicates: true });
	assert.equal(only(chosen.candidates).notes, "note\n\nAuthenticator key (TOTP): S");
	assert.equal(JSON.stringify(parsed), before);
});

test("the plan: an import that would pass 10,000 items in the vault says so, and makes no items", () => {
	assert.equal(ie.LIMITS.maxVaultItems, 10000);
	const vault = (n) => Array.from({ length: n }, (_, i) => ({ name: "Item " + i, username: null, password: null, urls: [] }));
	const input = csv(["a,,,p,", "b,,,p,", "Item 0,,,,"]);
	const fits = plan(input, vault(9998));
	assert.deepEqual([fits.counts.toAdd, fits.counts.vaultItemsBefore, fits.counts.vaultItemsAfter, fits.counts.exceedsVaultItemLimit], [2, 9998, 10000, false]);
	assert.equal(ie.createItems(fits, new Date()).length, 2);
	const over = plan(input, vault(9999));
	assert.deepEqual([over.counts.vaultItemsAfter, over.counts.exceedsVaultItemLimit], [10001, true]);
	assert.throws(() => ie.createItems(over, new Date()), (e) => e instanceof ie.ImportRefused && e.code === "vault_item_limit" && e.message === ie.REFUSAL_TEXTS.vault_item_limit);
	// Duplicates that are skipped do not count towards it; imported too, they do.
	assert.equal(plan(input, vault(9999), { importDuplicates: true }).counts.vaultItemsAfter, 10002);
});

// ---------------------------------------------------------------- the items a plan adds (§10)
test("the items: new identifiers, the time of the import, empty values as none, and exactly what the vault's own validation accepts", () => {
	const now = new Date("2026-11-10T12:34:56.789Z");
	const p = plan(csv(["\" Example \",\"example.com\nandroid://x\",\" u \",\" p \",\" n \"", "Only a name,,,,", "skipped,,," + "p".repeat(4097) + ",", "Only a name,,,,"]), []);
	const items = ie.createItems(p, now);
	assert.equal(items.length, 2);
	assert.deepEqual(items.map((i) => [i.type, i.name, i.username, i.password, [...i.urls], i.notes, i.favorite]), [
		["login", "Example", " u ", " p ", ["https://example.com"], " n ", false], ["login", "Only a name", null, null, [], null, false]
	]);
	for (const item of items) {
		assert.match(item.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		assert.equal(item.createdAt, now);
		assert.equal(item.updatedAt, now);
		assert.equal(item.createdAtText, null);
		assert.ok(Object.isFrozen(item) && Object.isFrozen(item.urls));
		vc.validateItem(item);
	}
	assert.notEqual(items[0].id, items[1].id);
	// Each call makes new identifiers: none comes from the file or from an earlier call.
	const again = ie.createItems(p, now);
	assert.ok(again.every((a) => items.every((b) => a.id !== b.id)));
	// They are written into the vault's own document and read back from it unchanged.
	const round = vc.parseVault(vc.serializeVault({ items })).items;
	assert.deepEqual(round.map((i) => [i.id, i.name, i.username, i.password, [...i.urls], i.notes, i.favorite, i.createdAt.getTime()]),
		items.map((i) => [i.id, i.name, i.username, i.password, [...i.urls], i.notes, i.favorite, now.getTime()]));
});

test("the items: every candidate of every fixture that is to be added passes the vault's own validation", () => {
	let checked = 0;
	for (const name of conformance.expectedFiles()) {
		const expected = conformance.readExpected(name);
		for (const c of expected.cases) {
			if (c.result.refused) { continue; }
			// The desktop's own candidates, as the fixtures list them: what it adds, this vault can store.
			const fake = { counts: { exceedsVaultItemLimit: false }, candidates: c.result.candidates };
			for (const item of ie.createItems(fake, new Date())) { vc.validateItem(item); checked++; }
		}
	}
	assert.ok(checked > 200, `${checked} items`);
});

test("the items: do not keep the text of the file alive (they are copies, not pieces of it)", async (t) => {
	let gc;
	try { require("node:v8").setFlagsFromString("--expose-gc"); gc = require("node:vm").runInNewContext("gc"); } catch (e) { gc = null; }
	if (typeof gc !== "function") { t.skip("this runtime does not let a test collect garbage"); return; }
	// The text of a file is a string on the JavaScript heap; what the heap holds once the garbage
	// is collected is what is still referenced. (The bytes of the file are freed on their own time.)
	const pause = () => new Promise((resolve) => setTimeout(resolve, 20));
	async function heldOver(baseline, limit) {
		let held = Infinity;
		for (let attempt = 0; attempt < 10 && held >= limit; attempt++) {
			if (attempt > 0) { await pause(); }
			gc(); gc();
			held = process.memoryUsage().heapUsed - baseline;
		}
		return held;
	}
	// Some 13 MiB in 10,000 rows, of which a hundred and one are added (the rest are duplicates of the last of them).
	function largeFile() {
		const rest = ",https://example.com/a/rather/long/path/to/be/sure,fake.user@example.test,FAKE-password-of-some-length,";
		const unique = Array.from({ length: 100 }, (_, i) => "unique name number " + i + " of the hundred" + rest + "notes of some length too\n").join("");
		return utf8("name,url,username,password,note\n" + unique + ("fake name that is long enough to be a piece of the file" + rest + "n".repeat(1300) + "\n").repeat(9900));
	}
	const MIB = 1024 * 1024;
	gc(); gc();
	const baseline = process.memoryUsage().heapUsed;

	// What the check is able to see: a hundred and one small pieces of the file, kept as they are cut.
	let pieces = (function () {
		const parsed = ie.parseImport(largeFile());
		return parsed.entries.slice(0, 101).map((entry) => entry.name);
	})();
	const heldByPieces = await heldOver(baseline, 4 * MIB);
	t.diagnostic(`101 names cut from a 13 MiB file hold ${Math.round(heldByPieces / MIB)} MiB of it in this runtime`);
	assert.equal(pieces.length, 101);
	pieces = null;

	let items = (function () {
		const file = largeFile();
		assert.ok(file.length > 13 * MIB);
		const made = ie.createItems(ie.planImport(ie.parseImport(file), [], NO_OPTIONS), new Date());
		assert.equal(made.length, 101);
		return made;
	})();
	const heldByItems = await heldOver(baseline, 4 * MIB);
	assert.ok(heldByItems < 4 * MIB, `${Math.round(heldByItems / MIB)} MiB are still held by 101 small items`);
	assert.equal(items[0].name, "unique name number 0 of the hundred");
	assert.equal(items[100].notes.length, 1300);
	items = null;
});

// -------------------------------------------------------------- reading the chosen file
test("the file: its size is looked at before anything is read, and never more than the limit and one byte is read", async () => {
	const tooLarge = { size: ie.LIMITS.maxFileBytes + 1, slice() { throw new Error("a file that is too large must not be read"); } };
	await assert.rejects(ie.readFileBytes(tooLarge), (e) => e instanceof ie.ImportRefused && e.code === "too_large");
	// A file that says it is small and is not: only the limit and one byte are asked for, and what arrives is counted again.
	const asked = [];
	const lying = { size: 10, slice(from, to) { asked.push([from, to]); return new Blob([new Uint8Array(to - from)]); } };
	await assert.rejects(ie.readFileBytes(lying), (e) => e instanceof ie.ImportRefused && e.code === "too_large");
	assert.deepEqual(asked, [[0, ie.LIMITS.maxFileBytes + 1]]);
	// At the limit it is read, and the bytes are the file's.
	const exact = new Blob([new Uint8Array(ie.LIMITS.maxFileBytes).fill(0x61)]);
	assert.equal((await ie.readFileBytes(exact)).length, ie.LIMITS.maxFileBytes);
	const small = await ie.readFileBytes(new Blob(["name,password\nfake,FAKE-pw\n"]));
	assert.ok(small instanceof Uint8Array);
	assert.equal(text(small), "name,password\nfake,FAKE-pw\n");
	assert.equal((await ie.readFileBytes(new Blob([]))).length, 0);
	// What is not a file is not read, and a file the browser cannot read says so in its own way.
	await assert.rejects(ie.readFileBytes(null), TypeError);
	await assert.rejects(ie.readFileBytes({ size: "1" }), TypeError);
	await assert.rejects(ie.readFileBytes({ size: 1, slice() { return { arrayBuffer() { return Promise.reject(new Error("NotReadableError")); } }; } }), (e) => !(e instanceof ie.ImportRefused));
});

// ------------------------------------------------------------------------ export (§11)
const at = new Date("2026-11-10T12:00:00.999Z");
function item(fields) {
	const created = new Date("2025-03-04T05:06:07Z");
	return Object.assign({ id: "0b1705e0-0000-4000-8000-000000000001", type: "login", name: "Example", username: null, password: null, urls: [], notes: null, favorite: false,
		createdAt: created, updatedAt: created, createdAtText: null }, fields);
}

test("export csv: Chrome's layout, every value quoted, quotes doubled, CR LF after every line, values exactly as they are", () => {
	const items = [
		item({ name: "Example Mail", username: "fake.user@example.test", password: "FAKE-mail-pw-1", urls: ["https://mail.example.com/login"], notes: "The address book is shared." }),
		item({ name: "Two addresses", username: "fake.two", password: "FAKE-two-pw", urls: ["https://first.example.org/", "https://second.example.org/"] }),
		item({ name: "Quotes \"and\", commas", username: "fake,\"user\"", password: "FAKE \"pw\", with a comma", notes: "line one\nline two\r\nline three, with a \"quote\"" }),
		item({ name: "=SUM(1,2)", username: "=fake", password: "+FAKE-@formula", notes: "@note -x\t|cmd" }),
		item({ name: "Spaces kept", username: "  fake spaced  ", password: "  FAKE spaced pw  ", notes: "  notes  " }),
		item({ name: "Only a name" })
	];
	assert.equal(text(ie.exportCsv(items)),
		"name,url,username,password,note\r\n" +
		"\"Example Mail\",\"https://mail.example.com/login\",\"fake.user@example.test\",\"FAKE-mail-pw-1\",\"The address book is shared.\"\r\n" +
		"\"Two addresses\",\"https://first.example.org/\",\"fake.two\",\"FAKE-two-pw\",\"\"\r\n" +
		"\"Quotes \"\"and\"\", commas\",\"\",\"fake,\"\"user\"\"\",\"FAKE \"\"pw\"\", with a comma\",\"line one\nline two\r\nline three, with a \"\"quote\"\"\"\r\n" +
		"\"=SUM(1,2)\",\"\",\"=fake\",\"+FAKE-@formula\",\"@note -x\t|cmd\"\r\n" +   // nothing is put in front of a value
		"\"Spaces kept\",\"\",\"  fake spaced  \",\"  FAKE spaced pw  \",\"  notes  \"\r\n" +
		"\"Only a name\",\"\",\"\",\"\",\"\"\r\n");
	// No byte order mark; an empty vault is the header line alone.
	assert.deepEqual([...ie.exportCsv(items).slice(0, 4)], [0x6E, 0x61, 0x6D, 0x65]);
	assert.equal(text(ie.exportCsv([])), "name,url,username,password,note\r\n");
	assert.equal(text(ie.exportVault(items, ie.EXPORT_CSV, at)), text(ie.exportCsv(items)));
	assert.equal(ie.countItemsWithSeveralUrls(items), 1);
	assert.equal(ie.countItemsWithSeveralUrls([]), 0);
});

test("export json: the format, the members in their order, empty strings for what an item does not have", () => {
	const items = [
		item({ name: "Example", username: "fake.user@example.test", password: "FAKE-pw", urls: ["https://example.com/login"], favorite: true,
			createdAt: new Date("2025-01-02T03:04:05.123Z"), createdAtText: "2025-01-02T03:04:05.1234567+00:00", updatedAt: new Date("2026-02-03T04:05:06Z"), updatedAtText: "2026-02-03T04:05:06+00:00" }),
		item({ name: "Only a name" })
	];
	const bytes = ie.exportJson(items, at);
	assert.equal(text(bytes), `{
  "format": "bitosx-export",
  "version": 1,
  "exportedAt": "2026-11-10T12:00:00Z",
  "items": [
    {
      "type": "login",
      "name": "Example",
      "username": "fake.user@example.test",
      "password": "FAKE-pw",
      "urls": [
        "https://example.com/login"
      ],
      "notes": "",
      "favorite": true,
      "createdAt": "2025-01-02T03:04:05.1234567Z",
      "updatedAt": "2026-02-03T04:05:06Z"
    },
    {
      "type": "login",
      "name": "Only a name",
      "username": "",
      "password": "",
      "urls": [],
      "notes": "",
      "favorite": false,
      "createdAt": "2025-03-04T05:06:07Z",
      "updatedAt": "2025-03-04T05:06:07Z"
    }
  ]
}
`);
	assert.deepEqual(JSON.parse(text(ie.exportJson([], at))), { format: "bitosx-export", version: 1, exportedAt: "2026-11-10T12:00:00Z", items: [] });
	assert.equal(text(ie.exportVault(items, ie.EXPORT_JSON, at)), text(bytes));
	assert.throws(() => ie.exportVault(items, "xml", at), RangeError);
	// What is written is strict JSON by this importer's own measure.
	assert.doesNotThrow(() => ie._parseJsonStrict(text(bytes)));
});

test("export: times are UTC and end in Z; an item's keep their fraction, up to seven digits, without trailing zeros", () => {
	const stamp = (dateText, vaultText) => ie._itemTimestamp(new Date(dateText), vaultText);
	// The text the desktop wrote, while it still says the same instant: seven digits survive.
	assert.equal(stamp("2025-03-05T05:06:07.123Z", "2025-03-05T05:06:07.1234567+00:00"), "2025-03-05T05:06:07.1234567Z");
	assert.equal(stamp("2025-03-05T05:06:07.120Z", "2025-03-05T05:06:07.1200000+00:00"), "2025-03-05T05:06:07.12Z");
	assert.equal(stamp("2025-03-05T05:06:07.000Z", "2025-03-05T05:06:07.0000000+00:00"), "2025-03-05T05:06:07Z");
	assert.equal(stamp("2025-03-05T05:06:07.000Z", "2025-03-05T05:06:07.0000001Z"), "2025-03-05T05:06:07.0000001Z");
	assert.equal(stamp("2025-03-05T05:06:07.999Z", "2025-03-05T05:06:07.9999999+00:00"), "2025-03-05T05:06:07.9999999Z");
	assert.equal(stamp("2025-03-05T05:06:07Z", "2025-03-05T05:06:07Z"), "2025-03-05T05:06:07Z");
	// Another offset is converted to UTC; the fraction is not touched by that.
	assert.equal(stamp("2025-03-05T03:06:07.500Z", "2025-03-05T05:06:07.5000001+02:00"), "2025-03-05T03:06:07.5000001Z");
	assert.equal(stamp("2025-03-05T10:36:07.250Z", "2025-03-04T23:06:07.25-11:30"), "2025-03-05T10:36:07.25Z");
	// No text, or a text that no longer says the instant (the item was changed here): the Date decides.
	assert.equal(stamp("2026-11-10T12:34:56.789Z", null), "2026-11-10T12:34:56.789Z");
	assert.equal(stamp("2026-11-10T12:34:56.700Z", undefined), "2026-11-10T12:34:56.7Z");
	assert.equal(stamp("2026-11-10T12:34:56.000Z", null), "2026-11-10T12:34:56Z");
	assert.equal(stamp("2026-11-10T12:34:56.789Z", "2025-03-05T05:06:07.1234567+00:00"), "2026-11-10T12:34:56.789Z");
	assert.equal(stamp("2026-11-10T12:34:56.789Z", "nonsense"), "2026-11-10T12:34:56.789Z");
	// exportedAt is to the second.
	assert.equal(JSON.parse(text(ie.exportJson([], new Date("2026-12-31T23:59:59.999Z")))).exportedAt, "2026-12-31T23:59:59Z");
});

test("export: half of a surrogate pair is written as U+FFFD, in both formats, and what is written is read back", () => {
	const broken = item({ name: "half \uD83D here", username: "\uDD11", password: "ok \uD83D\uDD11 \uD83D", urls: ["https://example.com/"], notes: "\uD83D\uD83D\uDD11\uDD11" });
	const wanted = { name: "half \uFFFD here", username: "\uFFFD", password: "ok \uD83D\uDD11 \uFFFD", notes: "\uFFFD\uD83D\uDD11\uFFFD" };
	const fromJson = only(candidates(ie.exportJson([broken], at)));
	const fromCsv = only(candidates(ie.exportCsv([broken])));
	for (const got of [fromJson, fromCsv]) {
		assert.deepEqual({ name: got.name, username: got.username, password: got.password, notes: got.notes }, wanted);
	}
	assert.equal(ie._wellFormed("plain \uD83D\uDD11"), "plain \uD83D\uDD11");
	// The same without the runtime's own toWellFormed.
	const original = String.prototype.toWellFormed;
	try {
		String.prototype.toWellFormed = undefined;
		assert.equal(ie._wellFormed("a\uD83Db\uDD11c\uD83D\uDD11\uD83D"), "a\uFFFDb\uFFFDc\uD83D\uDD11\uFFFD");
		assert.equal(ie._wellFormed(""), "");
	} finally { String.prototype.toWellFormed = original; }
});

test("export: the file name is BitosX-export-YYYY-MM-DD with the local date", () => {
	assert.equal(ie.exportFileName(ie.EXPORT_CSV, new Date(2026, 10, 10, 23, 59)), "BitosX-export-2026-11-10.csv");
	assert.equal(ie.exportFileName(ie.EXPORT_JSON, new Date(2027, 0, 5, 0, 0)), "BitosX-export-2027-01-05.json");
	assert.throws(() => ie.exportFileName("xml", new Date()), RangeError);
});

// What the web vault holds after it opened a vault the desktop wrote with these items.
function fixtureVaultItems() {
	const exported = JSON.parse(text(fs.readFileSync(path.join(conformance.DIRECTORY, "bitosx-export.json"))));
	return exported.items.map((it, i) => Object.freeze({
		id: "0b1705e0-0000-4000-8000-" + String(i + 1).padStart(12, "0"), type: "login", name: it.name,
		username: it.username === "" ? null : it.username, password: it.password === "" ? null : it.password, urls: Object.freeze(it.urls.slice()),
		notes: it.notes === "" ? null : it.notes, favorite: it.favorite,
		// The vault's document says "+00:00" where the export says "Z".
		createdAt: new Date(it.createdAt), createdAtText: it.createdAt.replace(/Z$/, "+00:00"),
		updatedAt: new Date(it.updatedAt), updatedAtText: it.updatedAt.replace(/Z$/, "+00:00")
	}));
}

test("export: this vault's own exports of the fixture vault read back to the candidates of the desktop's two exports", () => {
	const items = fixtureVaultItems();
	assert.equal(items.length, 8);
	for (const [format, name] of [[ie.EXPORT_JSON, "bitosx-export.json.expected.json"], [ie.EXPORT_CSV, "bitosx-export.csv.expected.json"]]) {
		const expected = conformance.readExpected(name);
		const bytes = ie.exportVault(items, format, new Date("2026-11-10T12:00:00Z"));
		const out = conformance.runFixture({ ie, input: { bytes }, cases: expected.cases });
		assert.equal(expected.cases.length, 2);
		expected.cases.forEach((c, i) => assert.deepStrictEqual(out.results[i], c.result, `${format}, case "${c.name}"`));
	}
	// And the files themselves: the CSV is the desktop's byte for byte (the specification settles every
	// byte of it); the JSON says the same, with other escapes.
	assert.deepEqual(Buffer.from(ie.exportCsv(items)), fs.readFileSync(path.join(conformance.DIRECTORY, "bitosx-export.csv")));
	assert.deepEqual(JSON.parse(text(ie.exportJson(items, new Date("2026-11-10T12:00:00Z")))), JSON.parse(text(fs.readFileSync(path.join(conformance.DIRECTORY, "bitosx-export.json")))));
});

test("export then import: into the vault it came from, JSON adds nothing; CSV adds only the items that had more than one address", () => {
	const items = fixtureVaultItems().concat([
		item({ id: "0b1705e0-0000-4000-8000-0000000000a1", name: "  trimmed for the comparison  ", username: " u ", urls: ["https://example.com/"] }),
		item({ id: "0b1705e0-0000-4000-8000-0000000000a2", name: "Three addresses", urls: ["https://a.example/", "https://b.example/", "https://c.example/"] }),
		item({ id: "0b1705e0-0000-4000-8000-0000000000a3", name: "White space only", username: " ", password: "\t", notes: "\n" })
	]);
	const json = plan(ie.exportJson(items, at), items);
	assert.equal(json.label, "BitosX (JSON)");
	assert.deepEqual([json.counts.toAdd, json.counts.duplicates, json.counts.notImported, json.counts.empty], [0, items.length, 0, 0]);
	const csvPlan = plan(ie.exportCsv(items), items);
	assert.equal(csvPlan.label, "Chrome or Edge (CSV)");
	assert.equal(ie.countItemsWithSeveralUrls(items), 2);
	assert.deepEqual([csvPlan.counts.toAdd, csvPlan.counts.duplicates, csvPlan.counts.notImported, csvPlan.counts.empty], [2, items.length - 2, 0, 0]);
	assert.deepEqual(csvPlan.candidates.filter((c) => c.status === "add").map((c) => c.name), ["Two addresses", "Three addresses"]);
	// Into an empty vault everything comes back as it was stored (the name trimmed, as an import does).
	const back = ie.createItems(plan(ie.exportJson(items, at), []), at);
	assert.deepEqual(back.map((i) => [i.name, i.username, i.password, [...i.urls], i.notes, i.favorite]),
		items.map((i) => [ie._trim(i.name), i.username, i.password, [...i.urls], i.notes, i.favorite]));
});

test("export then import: every item of a vault of generated values survives both formats unchanged", () => {
	const random = seeded(11);
	const pick = (list) => list[Math.floor(random() * list.length)];
	const pieces = ["a", "B", "0", " ", "  ", "\"", "\"\"", ",", "\n", "\r\n", "\r", "\t", "\\", "\\\"", "'", ";", "=", "+", "-", "@", "\u00E9", "\u00DF", "\u65E5\u672C", "\uD83D\uDD11", "\u0000", "\u001F", "\u007F",
		"\u0085", "\u00A0", "\u2028", "\u2029", "\uFEFF", "\uFFFD", "\uFFFE", "\uFFFF", "<b>", "&amp;", "</script>", "{", "}", "[", "]", ":", "null", "\\u0041", "\\n"];
	const value = (max) => { let s = ""; for (let i = 0, n = Math.floor(random() * max); i < n; i++) { s += pick(pieces); } return s; };
	const items = [];
	for (let i = 0; i < 400; i++) {
		items.push(item({ id: "0b1705e0-0000-4000-8000-" + String(i).padStart(12, "0"), name: "n" + i + value(4), username: value(3) || null, password: value(5) || null,
			urls: random() < 0.3 ? [] : ["https://example.com/" + i], notes: value(6) || null, favorite: random() < 0.3 }));
	}
	const fromJson = plan(ie.exportJson(items, at), []);
	const fromCsv = plan(ie.exportCsv(items), []);
	assert.deepEqual([fromJson.counts.toAdd, fromCsv.counts.toAdd], [400, 400]);
	items.forEach((it, i) => {
		for (const got of [fromJson.candidates[i], fromCsv.candidates[i]]) {
			assert.deepEqual([got.name, got.username, got.password, got.urls, got.notes], [ie._trim(it.name), it.username || "", it.password || "", [...it.urls], it.notes || ""], "item " + i);
		}
		assert.equal(fromJson.candidates[i].favorite, it.favorite);
	});
	// Importing either export into the vault itself adds nothing.
	assert.equal(plan(ie.exportJson(items, at), items).counts.toAdd, 0);
	assert.equal(plan(ie.exportCsv(items), items).counts.toAdd, 0);
});

// -------------------------------------------------------- codes, texts and the vault's own rule
test("texts: every code has its fixed text, and a refusal carries the code, the text and nothing of the file", () => {
	for (const table of [ie.REFUSAL_TEXTS, ie.REASON_TEXTS, ie.EXTRA_TEXTS, ie.UNSUPPORTED_TEXTS, ie.TEXTS]) {
		assert.ok(Object.isFrozen(table));
		for (const [code, words] of Object.entries(table)) { assert.ok(typeof words === "string" && words.length > 0, code); }
	}
	assert.equal(Object.keys(ie.REFUSAL_TEXTS).length, 16);
	assert.equal(Object.keys(ie.REASON_TEXTS).length, 10);
	assert.deepEqual(Object.keys(ie.EXTRA_TEXTS), ["totp", "folder", "other_address", "custom_field"]);
	assert.deepEqual(Object.keys(ie.UNSUPPORTED_TEXTS), ["secure_note", "card", "identity", "ssh_key", "bank_account", "drivers_license", "passport", "other"]);
	const r = refusal("name,password\n\"FAKE-secret-marker");
	assert.deepEqual([r.name, r.code, r.line, r.message], ["ImportRefused", "invalid_csv", 2, ie.REFUSAL_TEXTS.invalid_csv]);
	assert.ok(r instanceof Error);
	assert.equal(refusal("").line, null);
	// The words both clients use, where a person is asked or told something.
	assert.equal(ie.TEXTS.optionCopyExtrasToNotes, "Copy what BitosX has no field for into each item's notes");
	assert.equal(ie.TEXTS.optionImportDuplicates, "Import duplicates too");
	assert.equal(ie.TEXTS.fileStillHoldsPasswords, "The file you imported still holds every password in plain text. Delete it when you no longer need it.");
	assert.equal(ie.TEXTS.exportWarning, "This file will contain every password in plain text. Anyone who can read it can sign in as you. Keep it only as long as you need it, and delete it afterwards. Do not open it in a spreadsheet program: such programs can run formulas found in files like this. To keep a copy of your vault, use the encrypted backup instead.");
	assert.equal(ie.TEXTS.exportAcknowledgement, "I understand that this file is not encrypted");
});

test("the vault's own rule for an address is one function, which its validation and the import both ask", () => {
	for (const url of ["https://example.com", "http://example.com:8080/a?b#c", "HTTPS://EXAMPLE.COM", "https://user:pw@example.com/", "http://[::1]/", "http://localhost"]) { assert.equal(vc.isValidUrl(url), true, url); }
	for (const url of ["", "example.com", "ftp://example.com", "javascript:alert(1)", "https://", "https://example.com:99999", "mailto:a@b.c", "//example.com", null, undefined, 5, {}]) { assert.equal(vc.isValidUrl(url), false, String(url)); }
	const base = { id: "0b1705e0-0000-4000-8000-000000000001", name: "n", username: null, password: null, notes: null, favorite: false, createdAt: new Date(), updatedAt: new Date() };
	vc.validateItem(Object.assign({}, base, { urls: ["https://example.com"] }));
	assert.throws(() => vc.validateItem(Object.assign({}, base, { urls: ["http://intranet.42"] })), (e) => e instanceof vc.VaultError && e.message === "'http://intranet.42' is not a valid absolute http(s) URL.");
});
