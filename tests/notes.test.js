// Secure notes (phase 13): the stored form of a note item and the content schema versions 1, 2
// and 3 — vault/public/assets/js/vault-crypto.js under Node's test runner.
//
//   node --test tests/notes.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const factory = require("../vault/public/assets/js/vault-crypto.js");
const vc = factory(null, globalThis.crypto);

const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => Buffer.from(bytes).toString("utf8");

const LOGIN = { type: "login", Id: "11111111-1111-4111-8111-111111111111", Name: "Login", Favorite: false, CreatedAt: "2026-10-01T09:00:00+00:00", UpdatedAt: "2026-10-01T09:00:00+00:00", Urls: [] };
const NOTE = { type: "note", Id: "22222222-2222-4222-8222-222222222222", Name: "Note", Notes: "line one\nline two", Favorite: true, CreatedAt: "2026-10-02T09:00:00+00:00", UpdatedAt: "2026-10-03T09:00:00+00:00" };
const TOTP = { Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6, Period: 30 };
const doc = (version, items) => utf8(JSON.stringify({ schemaVersion: version, items }));
function refusedContent(bytes, what) {
	assert.throws(() => vc.parseVault(bytes), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.CONTENT, what);
}

const NOW = new Date("2026-11-15T08:00:00Z");
const login = (patch) => Object.assign({ id: "11111111-1111-4111-8111-111111111111", type: "login", name: "Login", username: "u", password: "p", urls: ["https://example.com"], notes: null, favorite: false, createdAt: NOW, updatedAt: NOW }, patch || {});
const note = (patch) => Object.assign({ id: "33333333-3333-4333-8333-333333333333", type: "note", name: "Note", notes: "the text", favorite: false, createdAt: NOW, updatedAt: NOW }, patch || {});

// ------------------------------------------------------------- reading
test("a version 3 document is read, and a note comes out as a note with no login fields", () => {
	const vault = vc.parseVault(doc(3, [LOGIN, NOTE]));
	assert.equal(vault.schemaVersion, 3);
	assert.equal(vault.items.length, 2);
	assert.equal(vault.items[0].type, "login");
	const n = vault.items[1];
	assert.equal(n.type, "note");
	assert.ok(vc.isNoteItem(n) && !vc.isNoteItem(vault.items[0]));
	assert.equal(n.id, "22222222-2222-4222-8222-222222222222");
	assert.equal(n.name, "Note");
	assert.equal(n.notes, "line one\nline two");
	assert.equal(n.favorite, true);
	assert.equal(n.createdAt.toISOString(), "2026-10-02T09:00:00.000Z");
	assert.equal(n.updatedAt.toISOString(), "2026-10-03T09:00:00.000Z");
	assert.equal(n.username, null);
	assert.equal(n.password, null);
	assert.equal(n.totp, null);
	assert.deepEqual([...n.urls], []);
	assert.ok(Object.isFrozen(n) && Object.isFrozen(n.urls));
	// A version 3 document of logins only (with or without keys), or of nothing, is read too.
	assert.equal(vc.parseVault(doc(3, [LOGIN])).items.length, 1);
	assert.equal(vc.parseVault(doc(3, [Object.assign({}, LOGIN, { Totp: TOTP })])).items[0].totp.secret, TOTP.Secret);
	assert.equal(vc.parseVault(doc(3, [])).items.length, 0);
});

test("a note's text may be absent or empty: a note with only a name is a note", () => {
	const bare = Object.assign({}, NOTE);
	delete bare.Notes;
	assert.equal(vc.parseVault(doc(3, [bare])).items[0].notes, null);
	assert.equal(vc.parseVault(doc(3, [Object.assign({}, NOTE, { Notes: "" })])).items[0].notes, "");
	assert.equal(vc.parseVault(doc(3, [Object.assign({}, NOTE, { Notes: null })])).items[0].notes, null);
});

test("a note in a version 1 or 2 document is refused, as is version 4 and above", () => {
	refusedContent(doc(1, [NOTE]), "note in v1");
	refusedContent(doc(2, [NOTE]), "note in v2");
	refusedContent(doc(1, [LOGIN, NOTE]), "note after a login in v1");
	refusedContent(doc(2, [Object.assign({}, LOGIN, { Totp: TOTP }), NOTE]), "note after a keyed login in v2");
	for (const version of [4, 5, 100]) {
		refusedContent(doc(version, []), "v" + version + " empty");
		refusedContent(doc(version, [NOTE]), "v" + version + " with a note");
	}
	// A key in a version 1 document stays invalid.
	refusedContent(doc(1, [Object.assign({}, LOGIN, { Totp: TOTP })]), "key in v1");
});

test("a note with a login field, an unknown field or an unknown type is refused, and nothing else is looser", () => {
	for (const member of [{ Username: "u" }, { Password: "p" }, { Urls: [] }, { Urls: ["https://x.example"] }, { Totp: TOTP }, { Extra: 1 }, { notes: "x" }]) {
		refusedContent(doc(3, [Object.assign({}, NOTE, member)]), JSON.stringify(member));
	}
	for (const type of ["Note", "NOTE", "secure_note", "card", "", null, 2]) {
		refusedContent(doc(3, [Object.assign({}, NOTE, { type })]), "type " + type);
	}
	const noType = Object.assign({}, NOTE);
	delete noType.type;
	refusedContent(doc(3, [noType]), "no type");
	refusedContent(doc(3, [Object.assign({}, NOTE, { Id: "not-a-uuid" })]), "bad id");
	refusedContent(doc(3, [NOTE, Object.assign({}, NOTE)]), "duplicate id");
	refusedContent(doc(3, [Object.assign({}, NOTE, { Id: LOGIN.Id }), LOGIN]), "a note and a login with one id");
	refusedContent(doc(3, [Object.assign({}, NOTE, { Favorite: "yes" })]), "favorite");
	refusedContent(doc(3, [Object.assign({}, NOTE, { Notes: 12 })]), "notes not text");
	refusedContent(doc(3, [Object.assign({}, NOTE, { Name: [] })]), "name not text");
	refusedContent(doc(3, [Object.assign({}, NOTE, { CreatedAt: "yesterday" })]), "date");
	refusedContent(utf8(JSON.stringify({ schemaVersion: 3, items: [], other: 1 })), "unknown document member");
	// The refusal never quotes the content.
	try { vc.parseVault(doc(3, [Object.assign({}, NOTE, { Notes: "secret words", Password: "p" })])); }
	catch (e) { assert.ok(!e.message.includes("secret words")); }
});

// ------------------------------------------------------------- writing
test("a vault without notes is written exactly as before: version 1, or 2 with a key", () => {
	const before = '{"schemaVersion":1,"items":[{"type":"login","Username":"u","Password":"p","Urls":["https://example.com"],"Id":"11111111-1111-4111-8111-111111111111","Name":"Login","Favorite":false,"CreatedAt":"2026-11-15T08:00:00+00:00","UpdatedAt":"2026-11-15T08:00:00+00:00"}]}';
	assert.equal(text(vc.serializeVault({ items: [login()] })), before);
	const keyed = login({ totp: { secret: TOTP.Secret, algorithm: "SHA1", digits: 6, period: 30 } });
	assert.equal(text(vc.serializeVault({ items: [keyed] })).slice(0, 18), '{"schemaVersion":2');
	assert.equal(text(vc.serializeVault({ items: [] })), '{"schemaVersion":1,"items":[]}');
	assert.equal(vc.requiredSchemaVersion([]), 1);
	assert.equal(vc.requiredSchemaVersion([login()]), 1);
	assert.equal(vc.requiredSchemaVersion([keyed]), 2);
	assert.equal(vc.requiredSchemaVersion([note()]), 3);
	assert.equal(vc.requiredSchemaVersion([keyed, note()]), 3);
	assert.equal(vc.requiredSchemaVersion([note(), keyed]), 3);
});

test("a note is written as version 3: type, then the members every item has, in the login's order, nulls left out", () => {
	const written = text(vc.serializeVault({ items: [login(), note({ favorite: true })] }));
	assert.equal(written, '{"schemaVersion":3,"items":[' +
		'{"type":"login","Username":"u","Password":"p","Urls":["https://example.com"],"Id":"11111111-1111-4111-8111-111111111111","Name":"Login","Favorite":false,"CreatedAt":"2026-11-15T08:00:00+00:00","UpdatedAt":"2026-11-15T08:00:00+00:00"},' +
		'{"type":"note","Id":"33333333-3333-4333-8333-333333333333","Name":"Note","Notes":"the text","Favorite":true,"CreatedAt":"2026-11-15T08:00:00+00:00","UpdatedAt":"2026-11-15T08:00:00+00:00"}]}');
	// No text: no Notes member. An empty text is written as it is.
	assert.equal(text(vc.serializeVault({ items: [note({ notes: null })] })),
		'{"schemaVersion":3,"items":[{"type":"note","Id":"33333333-3333-4333-8333-333333333333","Name":"Note","Favorite":false,"CreatedAt":"2026-11-15T08:00:00+00:00","UpdatedAt":"2026-11-15T08:00:00+00:00"}]}');
	assert.ok(text(vc.serializeVault({ items: [note({ notes: "" })] })).includes('"Name":"Note","Notes":"","Favorite"'));
	// Text with markup, line ends and characters outside ASCII is escaped as the desktop's encoder does.
	assert.ok(text(vc.serializeVault({ items: [note({ notes: "<b>&</b>\r\nñ 🔐" })] })).includes('"Notes":"\\u003Cb\\u003E\\u0026\\u003C/b\\u003E\\r\\n\\u00F1 \\uD83D\\uDD10"'));
	// A note parsed from the empty login fields it carries in memory writes none of them.
	const back = vc.parseVault(utf8(written));
	assert.equal(text(vc.serializeVault(back)), written);
	// Removing the last note writes the lowest version again.
	assert.equal(text(vc.serializeVault({ items: back.items.filter((i) => i.type !== "note") })).slice(0, 18), '{"schemaVersion":1');
});

test("a note read in with its timestamps is written back with them exactly as read", () => {
	const raw = Object.assign({}, NOTE, { CreatedAt: "2026-10-01T09:00:00.1234567+00:00", UpdatedAt: "2026-10-02T10:11:12.9876543+00:00" });
	const written = text(vc.serializeVault(vc.parseVault(doc(3, [raw]))));
	assert.equal(written, '{"schemaVersion":3,"items":[{"type":"note","Id":"22222222-2222-4222-8222-222222222222","Name":"Note","Notes":"line one\\nline two","Favorite":true,' +
		'"CreatedAt":"2026-10-01T09:00:00.1234567+00:00","UpdatedAt":"2026-10-02T10:11:12.9876543+00:00"}]}');
});

test("a note is validated: a name of 1 to 200, a text of at most 16384, nothing of a login", () => {
	vc.validateItem(note());
	vc.validateItem(note({ notes: null }));
	vc.validateItem(note({ notes: "" }));
	vc.validateItem(note({ notes: "n".repeat(16384), name: "n".repeat(200) }));
	vc.validateItem(note({ username: null, password: null, totp: null, urls: [] }));   // the empty login fields a parsed note carries
	const bad = (patch, message) => assert.throws(() => vc.validateItem(note(patch)), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.CONTENT && e.message.includes(message), message);
	bad({ name: "" }, "Name is required");
	bad({ name: "   " }, "Name is required");
	bad({ name: "n".repeat(201) }, "at most 200");
	bad({ notes: "n".repeat(16385) }, "at most 16384");
	bad({ notes: 12 }, "at most 16384");
	bad({ notes: "half \uD83D" }, "incomplete character");
	bad({ username: "u" }, "only a name and a text");
	bad({ password: "p" }, "only a name and a text");
	bad({ urls: ["https://example.com"] }, "only a name and a text");
	bad({ totp: { secret: TOTP.Secret, algorithm: "SHA1", digits: 6, period: 30 } }, "only a name and a text");
	bad({ favorite: "yes" }, "Favorite");
	bad({ updatedAt: new Date("2020-01-01T00:00:00Z") }, "UpdatedAt");
	bad({ type: "card" }, "unknown type");
	// No message quotes the text.
	try { vc.validateItem(note({ notes: "secret words" + "x".repeat(16384) })); }
	catch (e) { assert.ok(!e.message.includes("secret words")); }
	// A login is validated as before, with or without its type.
	vc.validateItem(login());
	const untyped = login();
	delete untyped.type;
	vc.validateItem(untyped);
	assert.throws(() => vc.serializeVault({ items: [note(), note()] }), (e) => e.message.includes("duplicate"));
});
