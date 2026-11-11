// Import and export for the web vault (vault.bitosx.se).
//
// Import: the bytes of a file another password manager exported in, the logins it holds out, and
// the plan of what importing them into a vault would do. Export: the items of a vault as an
// unencrypted CSV or JSON file. The rules are those of the desktop application's
// docs/IMPORT_EXPORT.md (networkluki/bitosx), which both clients follow so that one file gives the
// same items in both; the section numbers in the comments below are that document's.
// tests/fixtures/import holds what the desktop makes of each file there, and this code is held
// against it under Node and in Chromium.
//
// Everything read from a file is untrusted. Nothing here touches the DOM, the network or the
// vault: bytes and plain objects in, plain objects out. The one thing taken from the browser is its
// XML parser (DOMParser), for KeePass 2 XML; it is handed in, so that everything else runs under
// Node as well. What these functions return holds the passwords of the file: the caller shows
// names, counts and reasons only, and lets go of it when the import is applied or cancelled.
// No text of a file is ever put into an error: refusals and reasons are fixed texts.
//
// Works as a browser global (window.bitosxImportExport, given window.bitosxVaultCrypto and
// window.DOMParser) and as a Node module (module.exports is the factory), like vault-crypto.js.
(function (root, factory) {
	"use strict";
	if (typeof module === "object" && module.exports) { module.exports = factory; }
	else { root.bitosxImportExport = factory(root.bitosxVaultCrypto, root.DOMParser); }
})(typeof self !== "undefined" ? self : this, function (vc, DOMParserCtor) {
	"use strict";

	// ---- §1 limits ----
	var MAX_FILE_BYTES = 16 * 1024 * 1024;
	var MAX_ENTRIES = 10000;
	var MAX_JSON_DEPTH = 64;
	var MAX_GROUP_DEPTH = 64;
	var MAX_XML_DEPTH = 100;
	var ITEM = vc.LIMITS;                 // the vault's own: name 200, username 320, password 4096, notes 16384, url 2048, urls 64
	var MAX_VAULT_ITEMS = vc.MAX_ITEMS;   // 10,000

	// ---- §13 codes and texts: fixed, the same in both clients, and never quoting a file ----
	var REFUSAL_TEXTS = Object.freeze({
		too_large: "The file is larger than 16 MiB. BitosX does not import files that large.",
		empty: "The file is empty.",
		unsupported_encoding: "The file is saved as UTF-16 or UTF-32 text. BitosX reads UTF-8: export the file again, or save it as UTF-8, and import that.",
		invalid_utf8: "The file is not UTF-8 text. BitosX reads exports saved as CSV, JSON or XML text in UTF-8; it cannot read a database file, or a file that is encrypted or compressed.",
		not_recognised: "BitosX does not recognise this file. It reads CSV files, Bitwarden's unencrypted JSON export, KeePass 2 XML and its own JSON export.",
		invalid_csv: "The CSV file is damaged: a value in quotes is not closed, or is followed by something other than a comma or the end of the line.",
		no_recognised_columns: "The file has no columns BitosX recognises. Its first line has to name a password column and at least one of name, url and username.",
		invalid_json: "The file is not JSON that BitosX can read: it is damaged, nested too deeply, uses a name twice in one object, or holds an incomplete character.",
		encrypted_export: "This Bitwarden export is encrypted. Export the vault from Bitwarden again as an unencrypted .json file, and import that.",
		unsupported_version: "This BitosX export was written by a newer version of BitosX. Update BitosX, and import the file again.",
		invalid_xml: "The file is not XML that BitosX can read: it is damaged or incomplete.",
		doctype: "The file contains a document type declaration (DOCTYPE). BitosX does not read XML files that have one.",
		protected_values: "The file holds values that are still encrypted (marked as protected). Export the database from KeePass as plain XML, and import that.",
		nested_too_deeply: "The file nests its groups or elements more deeply than BitosX reads.",
		too_many_entries: "The file holds more than 10,000 entries. BitosX imports at most 10,000 at a time: split the file, and import the parts.",
		vault_item_limit: "The vault would hold more than 10,000 items after this import, which is the most a vault can hold. Nothing was imported."
	});
	var REASON_TEXTS = Object.freeze({
		row_has_extra_values: "The row has more values than the file has columns.",
		field_twice: "The entry has the same field more than once.",
		name_too_long: "The name is longer than 200 characters.",
		username_too_long: "The username is longer than 320 characters.",
		password_too_long: "The password is longer than 4096 characters.",
		notes_too_long: "The notes are longer than 16384 characters.",
		too_many_urls: "The entry has more than 64 web addresses.",
		url_too_long: "A web address is longer than 2048 characters.",
		url_invalid: "A web address is not a valid http or https address.",
		notes_too_long_with_extras: "With the fields BitosX has no place for copied into them, the notes would be longer than 16384 characters."
	});
	// The kinds, in the order the fixtures and a preview list them, each "in the plural, in a sentence".
	var EXTRA_TEXTS = Object.freeze({
		totp: "authenticator keys (TOTP)",
		folder: "folder or group names",
		other_address: "addresses that are not web addresses",
		custom_field: "custom fields"
	});
	var UNSUPPORTED_TEXTS = Object.freeze({
		secure_note: "secure notes",
		card: "cards",
		identity: "identities",
		ssh_key: "SSH keys",
		bank_account: "bank accounts",
		drivers_license: "driver's licences",
		passport: "passports",
		other: "other items"
	});
	var TEXTS = Object.freeze({
		optionCopyExtrasToNotes: "Copy what BitosX has no field for into each item's notes",
		optionImportDuplicates: "Import duplicates too",
		fileStillHoldsPasswords: "The file you imported still holds every password in plain text. Delete it when you no longer need it.",
		exportWarning: "This file will contain every password in plain text. Anyone who can read it can sign in as you. "
			+ "Keep it only as long as you need it, and delete it afterwards. "
			+ "Do not open it in a spreadsheet program: such programs can run formulas found in files like this. "
			+ "To keep a copy of your vault, use the encrypted backup instead.",
		exportAcknowledgement: "I understand that this file is not encrypted",
		untitledName: "Untitled"
	});
	var NOTES_LABEL_TOTP = "Authenticator key (TOTP)";
	var NOTES_LABEL_FOLDER = "Folder";
	var NOTES_LABEL_OTHER_ADDRESS = "Other address";
	var NOTES_LABEL_NAMELESS_FIELD = "Field";

	// A file that is not read at all. code is one of REFUSAL_TEXTS; line only for invalid_csv.
	function ImportRefused(code, line) {
		this.name = "ImportRefused";
		this.code = code;
		this.line = typeof line === "number" ? line : null;
		this.message = REFUSAL_TEXTS[code];
	}
	ImportRefused.prototype = Object.create(Error.prototype);
	ImportRefused.prototype.constructor = ImportRefused;

	// KeePass 2 XML needs the browser's XML parser. Under Node there is none: this says so, and is
	// not a refusal of the file.
	function XmlParserUnavailable() {
		this.name = "XmlParserUnavailable";
		this.message = "No XML parser (DOMParser) is available here.";
	}
	XmlParserUnavailable.prototype = Object.create(Error.prototype);
	XmlParserUnavailable.prototype.constructor = XmlParserUnavailable;

	// ---- §2.1 the text operations, written out: trim() and toLowerCase() do other things ----
	function isTrimmedCode(c) {
		return (c >= 0x0009 && c <= 0x000D) || c === 0x0020 || c === 0x0085 || c === 0x00A0 || c === 0x1680
			|| (c >= 0x2000 && c <= 0x200A) || c === 0x2028 || c === 0x2029 || c === 0x202F || c === 0x205F
			|| c === 0x3000 || c === 0xFEFF;
	}
	function trim(value) {
		var start = 0, end = value.length;
		while (start < end && isTrimmedCode(value.charCodeAt(start))) { start++; }
		while (end > start && isTrimmedCode(value.charCodeAt(end - 1))) { end--; }
		return start === 0 && end === value.length ? value : value.slice(start, end);
	}
	function isBlank(value) {
		for (var i = 0; i < value.length; i++) { if (!isTrimmedCode(value.charCodeAt(i))) { return false; } }
		return true;
	}
	// A to Z become a to z; every other character stays as it is.
	function toLowerAscii(value) {
		if (!/[A-Z]/.test(value)) { return value; }
		return value.replace(/[A-Z]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) + 32); });
	}
	// Split at every CR LF, at every LF, and at every CR that no LF follows.
	function splitLines(value) { return value.split(/\r\n|\r|\n/); }
	function hasControlCharacter(value) { return /[\u0000-\u001F\u007F]/.test(value); }

	function isAsciiLetterCode(c) { return (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A); }
	function isAsciiDigitCode(c) { return c >= 0x30 && c <= 0x39; }
	function isAsciiLetterOrDigitCode(c) { return isAsciiLetterCode(c) || isAsciiDigitCode(c); }
	function isHexDigitCode(c) { return isAsciiDigitCode(c) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46); }
	function allDigits(text, from) {
		for (var i = from || 0; i < text.length; i++) { if (!isAsciiDigitCode(text.charCodeAt(i))) { return false; } }
		return true;
	}
	// The index of the first of the characters in `any`, or -1.
	function indexOfAny(text, any, from) {
		for (var i = from || 0; i < text.length; i++) { if (any.indexOf(text.charAt(i)) >= 0) { return i; } }
		return -1;
	}
	// The first character that is not a space, a tab, a carriage return or a line feed, or -1.
	function firstNonSpace(text) {
		for (var i = 0; i < text.length; i++) {
			var c = text.charCodeAt(i);
			if (c !== 0x20 && c !== 0x09 && c !== 0x0D && c !== 0x0A) { return i; }
		}
		return -1;
	}

	// ---- §2 reading a file: bytes to text, strictly ----
	function startsWith(bytes, prefix) {
		if (bytes.length < prefix.length) { return false; }
		for (var i = 0; i < prefix.length; i++) { if (bytes[i] !== prefix[i]) { return false; } }
		return true;
	}
	function decodeFile(bytes) {
		if (!(bytes instanceof Uint8Array)) { throw new TypeError("The file must be given as bytes."); }
		if (bytes.length > MAX_FILE_BYTES) { throw new ImportRefused("too_large"); }
		// UTF-32 before UTF-16: the little-endian marks start with the same two bytes.
		if (startsWith(bytes, [0x00, 0x00, 0xFE, 0xFF]) || startsWith(bytes, [0xFF, 0xFE, 0x00, 0x00])
			|| startsWith(bytes, [0xFE, 0xFF]) || startsWith(bytes, [0xFF, 0xFE])) {
			throw new ImportRefused("unsupported_encoding");
		}
		// The UTF-8 mark is removed once, here; ignoreBOM keeps the decoder from removing a second one.
		var view = startsWith(bytes, [0xEF, 0xBB, 0xBF]) ? bytes.subarray(3) : bytes;
		try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(view); }
		catch (e) { throw new ImportRefused("invalid_utf8"); }
	}

	// ---- §3.1 comma-separated records, one pass over the text ----
	// RFC 4180: a value whose first character is a double quote runs to the closing quote and may
	// hold commas and line ends; two quotes inside it stand for one; after the closing quote only a
	// comma, a line end or the end of the text may follow. Any other value is taken as it is. With
	// backslashEscapes (§3.4, KeePass CSV 1.x) a backslash inside a quoted value makes the character
	// after it part of the value, and a double quote always closes it. A fault is a refusal:
	// guessing what was meant could turn one password into another.
	function CsvRecordReader(text) {
		this.text = text;
		this.position = 0;
		this.line = 1;
		this.backslashEscapes = false;
	}
	// The next record as an array of values, or null at the end of the text. An empty line is a
	// record of one empty value.
	CsvRecordReader.prototype.readRecord = function () {
		var text = this.text, length = text.length;
		if (this.position >= length) { return null; }
		var values = [];
		for (;;) {
			values.push(text.charCodeAt(this.position) === 0x22 ? this.readQuotedValue() : this.readPlainValue());
			if (this.position >= length) { return values; }
			if (text.charCodeAt(this.position) === 0x2C) {
				this.position++;
				if (this.position >= length) { values.push(""); return values; } // the text ends after a comma: one more, empty, value
				continue;
			}
			// A line end: CR LF counts once.
			this.position += (text.charCodeAt(this.position) === 0x0D && text.charCodeAt(this.position + 1) === 0x0A) ? 2 : 1;
			this.line++;
			return values;
		}
	};
	CsvRecordReader.prototype.readPlainValue = function () {
		var text = this.text, length = text.length, start = this.position, i = start;
		while (i < length) {
			var c = text.charCodeAt(i);
			if (c === 0x2C || c === 0x0D || c === 0x0A) { break; }
			i++;
		}
		this.position = i;
		return text.slice(start, i);
	};
	CsvRecordReader.prototype.readQuotedValue = function () {
		var text = this.text, length = text.length;
		var openedOnLine = this.line;
		var escapes = this.backslashEscapes;
		var value = "";
		var i = this.position + 1;   // after the opening quote
		var from = i;                // what is in the value since the last cut
		for (;;) {
			if (i >= length) { throw new ImportRefused("invalid_csv", openedOnLine); } // never closed
			var c = text.charCodeAt(i);
			if (c === 0x22) {
				value += text.slice(from, i);
				if (!escapes && text.charCodeAt(i + 1) === 0x22) { value += "\""; i += 2; from = i; continue; }
				i++;   // the closing quote
				break;
			}
			if (c === 0x0D) { i += text.charCodeAt(i + 1) === 0x0A ? 2 : 1; this.line++; continue; } // kept as it is, and counted
			if (c === 0x0A) { i++; this.line++; continue; }
			if (escapes && c === 0x5C) {
				if (i + 1 >= length) { throw new ImportRefused("invalid_csv", openedOnLine); }
				value += text.slice(from, i);
				i++;
				from = i;   // the character after the backslash, whatever it is ...
				c = text.charCodeAt(i);
				if (c !== 0x0D && c !== 0x0A) { i++; }   // ... but a line end is still a line end, counted above
				continue;
			}
			i++;
		}
		this.position = i;
		if (i < length) {
			var next = text.charCodeAt(i);
			if (next !== 0x2C && next !== 0x0D && next !== 0x0A) { throw new ImportRefused("invalid_csv", this.line); } // something after the closing quote
		}
		return value;
	};

	// ---- §3.2 to §3.5 a comma-separated export of any password manager ----
	// For each field, the header names it is read from, in the order they are tried.
	var NAME_COLUMNS = ["name", "title", "account"];
	var URL_COLUMNS = ["url", "urls", "login_uri", "uri", "website", "web site"];
	var USERNAME_COLUMNS = ["username", "login_username", "user name", "login name"];
	var PASSWORD_COLUMNS = ["password", "login_password"];
	var NOTES_COLUMNS = ["note", "notes", "comments", "extra"];
	var FAVORITE_COLUMNS = ["favorite", "fav"];
	var TOTP_COLUMNS = ["totp", "login_totp", "otpauth"];
	var TYPE_COLUMNS = ["type"];
	var FOLDER_COLUMNS = ["folder", "group", "grouping"];
	var CUSTOM_FIELD_COLUMNS = ["fields"];

	// KeePass 2's "KeePass CSV (1.x)" export: the one layout with its own way of quoting.
	var KEEPASS1_HEADER = ["account", "login name", "password", "web site", "comments"];
	// The headers of the exporters whose source was read, exactly as they write them (in lower case).
	var KNOWN_HEADERS = [
		["Chrome or Edge (CSV)", ["name", "url", "username", "password", "note"]],
		["Chrome or Edge (CSV)", ["name", "url", "username", "password"]],
		["Firefox (CSV)", ["url", "username", "password", "httprealm", "formactionorigin", "guid", "timecreated", "timelastused", "timepasswordchanged"]],
		["Bitwarden (CSV)", ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "archiveddate", "login_uri", "login_username", "login_password", "login_totp"]],
		["Bitwarden (CSV)", ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"]],
		["Bitwarden (CSV)", ["collections", "type", "name", "notes", "fields", "reprompt", "archiveddate", "login_uri", "login_username", "login_password", "login_totp"]],
		["Bitwarden (CSV)", ["collections", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"]],
		["KeePassXC (CSV)", ["group", "title", "username", "password", "url", "notes", "totp", "icon", "last modified", "created"]],
		["KeePassXC (CSV)", ["group", "title", "username", "password", "url", "notes"]],
		["KeePass 1.x (CSV)", KEEPASS1_HEADER]
	];
	var UNSUPPORTED_ORDER = ["secure_note", "card", "identity", "ssh_key", "bank_account", "drivers_license", "passport", "other"];
	var EXTRA_ORDER = ["totp", "folder", "other_address", "custom_field"];

	function sameList(a, b) {
		if (a.length !== b.length) { return false; }
		for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
		return true;
	}
	function isBlankRecord(values) {
		for (var i = 0; i < values.length; i++) { if (!isBlank(values[i])) { return false; } }
		return true;
	}
	// The counts by kind as an object, in the fixed order, kinds with none left out.
	function countsInOrder(counts, order) {
		var out = {};
		order.forEach(function (kind) { if (counts[kind] > 0) { out[kind] = counts[kind]; } });
		return out;
	}
	function parsedImport(format, label, entries, records, unsupported, inTrash, ignoredColumns) {
		return {
			format: format, label: label, entries: entries, records: records,
			unsupported: countsInOrder(unsupported, UNSUPPORTED_ORDER), inTrash: inTrash, ignoredColumns: ignoredColumns
		};
	}
	// One login as a file holds it, before anything is normalised.
	function importEntry(position) {
		return {
			position: position, name: "", username: "", password: "", notes: "", favorite: false,
			addresses: [], totp: "", folder: "", customFields: [], problem: null
		};
	}

	// The custom fields of a Bitwarden row: one a line, "name: value", split at the last ": ". A
	// line without one is kept as a field without a name.
	function readCustomFieldsCell(cell) {
		var fields = [];
		if (cell.length === 0) { return fields; }
		splitLines(cell).forEach(function (line) {
			if (isBlank(line)) { return; }
			var separator = line.lastIndexOf(": ");
			fields.push(separator < 0
				? { name: "", value: line }
				: { name: trim(line.slice(0, separator)), value: line.slice(separator + 2) });
		});
		return fields;
	}

	function readCsv(text) {
		var reader = new CsvRecordReader(text);

		// The header is the first record that is not blank.
		var headerValues;
		do {
			headerValues = reader.readRecord();
			if (headerValues === null) { throw new ImportRefused("no_recognised_columns"); }
		} while (isBlankRecord(headerValues));

		var columnCount = headerValues.length;
		var header = new Array(columnCount);
		var firstColumnNamed = new Map();
		for (var i = 0; i < columnCount; i++) {
			header[i] = toLowerAscii(trim(headerValues[i]));
			if (header[i].length > 0 && !firstColumnNamed.has(header[i])) { firstColumnNamed.set(header[i], i); } // of two columns with one name, the left one
		}
		var foundName = null;
		function find(names) {
			for (var k = 0; k < names.length; k++) {
				if (firstColumnNamed.has(names[k])) { foundName = names[k]; return firstColumnNamed.get(names[k]); }
			}
			foundName = null;
			return -1;
		}
		var nameColumn = find(NAME_COLUMNS);
		var urlColumn = find(URL_COLUMNS);
		var urlColumnName = foundName;
		var usernameColumn = find(USERNAME_COLUMNS);
		var passwordColumn = find(PASSWORD_COLUMNS);
		var notesColumn = find(NOTES_COLUMNS);
		var favoriteColumn = find(FAVORITE_COLUMNS);
		var totpColumn = find(TOTP_COLUMNS);
		var typeColumn = find(TYPE_COLUMNS);
		var folderColumn = find(FOLDER_COLUMNS);
		var customFieldColumn = find(CUSTOM_FIELD_COLUMNS);

		if (passwordColumn < 0 || (nameColumn < 0 && urlColumn < 0 && usernameColumn < 0)) {
			throw new ImportRefused("no_recognised_columns");
		}

		// Bitwarden writes the addresses of an item into one cell, with commas between them.
		var addressesAreCommaSeparated = urlColumnName === "login_uri" || urlColumnName === "uri";

		var label = "CSV";
		for (var h = 0; h < KNOWN_HEADERS.length; h++) {
			if (sameList(header, KNOWN_HEADERS[h][1])) { label = KNOWN_HEADERS[h][0]; break; }
		}
		// KeePass writes a quote inside a value as \" and a backslash as \\ in this layout.
		if (sameList(header, KEEPASS1_HEADER)) { reader.backslashEscapes = true; }

		var used = new Set([nameColumn, urlColumn, usernameColumn, passwordColumn, notesColumn,
			favoriteColumn, totpColumn, typeColumn, folderColumn, customFieldColumn]);
		var ignoredColumns = [];
		for (var j = 0; j < columnCount; j++) {
			if (header[j].length > 0 && !used.has(j)) { ignoredColumns.push(trim(headerValues[j])); }
		}

		function cell(values, column) { return column >= 0 && column < values.length ? values[column] : ""; }

		var entries = [];
		var unsupported = {};
		var records = 0;
		for (var values = reader.readRecord(); values !== null; values = reader.readRecord()) {
			if (isBlankRecord(values)) { continue; }
			records++;
			if (records > MAX_ENTRIES) { throw new ImportRefused("too_many_entries"); }

			// The one value of a type column that is known to mean "not a login": Bitwarden's notes.
			if (toLowerAscii(trim(cell(values, typeColumn))) === "note") {
				unsupported.secure_note = (unsupported.secure_note || 0) + 1;
				continue;
			}

			var entry = importEntry(records);
			var addressCell = cell(values, urlColumn);
			var favorite = toLowerAscii(trim(cell(values, favoriteColumn)));
			entry.name = cell(values, nameColumn);
			entry.username = cell(values, usernameColumn);
			entry.password = cell(values, passwordColumn);
			entry.notes = cell(values, notesColumn);
			entry.favorite = favorite === "1" || favorite === "true";
			entry.addresses = addressCell.length === 0 ? [] : addressesAreCommaSeparated ? addressCell.split(",") : [addressCell];
			entry.totp = cell(values, totpColumn);
			entry.folder = cell(values, folderColumn);
			entry.customFields = readCustomFieldsCell(cell(values, customFieldColumn));
			// A value that is not empty to the right of the header's last column: an unquoted comma
			// moved the values, and the password may be half of what it was.
			for (var x = columnCount; x < values.length; x++) {
				if (values[x].length > 0) { entry.problem = "row_has_extra_values"; break; }
			}
			entries.push(entry);
		}

		return parsedImport("csv", label, entries, records, unsupported, 0, ignoredColumns);
	}

	// ---- §4.1 JSON, strictly ----
	// JSON.parse reads strict JSON, but accepts three things the specification refuses: more than
	// 64 arrays and objects inside one another, a name twice in one object, and half of a surrogate
	// pair in a name or a string. This pass over the text finds those three, without recursion and
	// before JSON.parse sees the text. It does not judge the syntax: text it cannot make sense of is
	// left to JSON.parse, which refuses it. Either way the answer is the same refusal.
	function checkJsonText(text) {
		var length = text.length;
		var stack = [];    // one frame for every open array (null) or object ({ names, expectName })
		var top = null;
		var i = 0;
		while (i < length) {
			var c = text.charCodeAt(i);
			if (c === 0x22) {
				// A string: a member name or a value. Its text, escapes resolved, has to be whole.
				var start = i + 1;
				var escaped = false;
				var expectLow = false;
				i = start;
				for (;;) {
					if (i >= length) { return; }   // never closed
					c = text.charCodeAt(i);
					if (c === 0x22) { break; }
					var unit = c;
					if (c === 0x5C) {
						escaped = true;
						if (text.charCodeAt(i + 1) === 0x75) {
							unit = hexUnit(text, i + 2);
							i += 6;
						} else {
							unit = 0;   // a two-character escape: never half of a pair
							i += 2;
						}
					} else {
						i++;
					}
					var isLow = unit >= 0xDC00 && unit <= 0xDFFF;
					if (isLow !== expectLow) { throw new ImportRefused("invalid_json"); } // a low half without a high one before it, or a high one without its low one
					expectLow = unit >= 0xD800 && unit <= 0xDBFF;
				}
				if (expectLow) { throw new ImportRefused("invalid_json"); }
				if (top !== null && top.expectName) {
					var name;
					if (escaped) {
						try { name = JSON.parse(text.slice(start - 1, i + 1)); }
						catch (e) { throw new ImportRefused("invalid_json"); }
					} else {
						name = text.slice(start, i);
					}
					if (top.names === null) { top.names = new Set(); }
					if (top.names.has(name)) { throw new ImportRefused("invalid_json"); }
					top.names.add(name);
					top.expectName = false;
				}
				i++;
				continue;
			}
			if (c === 0x7B || c === 0x5B) {
				if (stack.length >= MAX_JSON_DEPTH) { throw new ImportRefused("invalid_json"); }
				top = c === 0x7B ? { names: null, expectName: true } : null;
				stack.push(top);
			} else if (c === 0x7D || c === 0x5D) {
				stack.pop();
				top = stack.length > 0 ? stack[stack.length - 1] : null;
			} else if (c === 0x2C && top !== null) {
				top.expectName = true;
			}
			i++;
		}
	}
	// The UTF-16 unit of the four hexadecimal digits at `at`, or 0 if they are not four such digits
	// (JSON.parse then refuses the text).
	function hexUnit(text, at) {
		var unit = 0;
		for (var k = 0; k < 4; k++) {
			var c = text.charCodeAt(at + k);
			var digit = isAsciiDigitCode(c) ? c - 0x30 : (c >= 0x61 && c <= 0x66) ? c - 0x61 + 10 : (c >= 0x41 && c <= 0x46) ? c - 0x41 + 10 : -1;
			if (digit < 0) { return 0; }
			unit = unit * 16 + digit;
		}
		return unit;
	}
	function parseJsonStrict(text) {
		checkJsonText(text);
		try { return JSON.parse(text); }
		catch (e) { throw new ImportRefused("invalid_json"); } // the parser's message can quote the file: not passed on
	}

	// ---- reading one member, leniently: absent, null or of another type counts as absent ----
	var hasOwn = Object.prototype.hasOwnProperty;
	function isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
	function member(parent, name) { return hasOwn.call(parent, name) ? parent[name] : undefined; }
	function textOf(parent, name) { var v = member(parent, name); return typeof v === "string" ? v : ""; }
	function isTrue(parent, name) { return member(parent, name) === true; }
	function arrayOf(parent, name) { var v = member(parent, name); return Array.isArray(v) ? v : null; }
	function count(counts, kind) { counts[kind] = (counts[kind] || 0) + 1; }

	function readJson(text) {
		var root = parseJsonStrict(text);
		if (!isObject(root)) { throw new ImportRefused("not_recognised"); }
		if (textOf(root, "format") === "bitosx-export") { return readBitosXExport(root); }
		// Both of Bitwarden's encrypted exports say so here; the one protected by a password has no items at all.
		if (isTrue(root, "encrypted")) { throw new ImportRefused("encrypted_export"); }
		var items = arrayOf(root, "items");
		if (items !== null) { return readBitwardenExport(root, items); }
		throw new ImportRefused("not_recognised");
	}

	// §4.2. Bitwarden numbers its kinds, and a login is 1.
	var BITWARDEN_KINDS = { 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key", 6: "bank_account", 7: "drivers_license", 8: "passport" };
	function readBitwardenExport(root, items) {
		if (items.length > MAX_ENTRIES) { throw new ImportRefused("too_many_entries"); }

		// The folders of the export, by their id. Of two with one id, the first.
		var folderNames = new Map();
		var folders = arrayOf(root, "folders");
		if (folders !== null) {
			folders.forEach(function (folder) {
				if (!isObject(folder)) { return; }
				var id = textOf(folder, "id");
				if (id.length > 0 && !folderNames.has(id)) { folderNames.set(id, textOf(folder, "name")); }
			});
		}

		var entries = [];
		var unsupported = {};
		var inTrash = 0;
		for (var index = 0; index < items.length; index++) {
			var item = items[index];
			if (!isObject(item)) { count(unsupported, "other"); continue; }
			// In the trash, whatever it is.
			if (hasOwn.call(item, "deletedDate") && item.deletedDate !== null) { inTrash++; continue; }
			var type = member(item, "type");
			if (typeof type !== "number") { count(unsupported, "other"); continue; }
			if (type !== 1) { count(unsupported, hasOwn.call(BITWARDEN_KINDS, type) ? BITWARDEN_KINDS[type] : "other"); continue; }

			var entry = importEntry(index + 1);
			var login = member(item, "login");
			if (isObject(login)) {
				entry.username = textOf(login, "username");
				entry.password = textOf(login, "password");
				entry.totp = textOf(login, "totp");
				var uris = arrayOf(login, "uris");
				if (uris !== null) {
					for (var u = 0; u < uris.length; u++) {
						if (!isObject(uris[u])) { continue; }
						var address = textOf(uris[u], "uri");
						if (address.length > 0) { entry.addresses.push(address); }
					}
				}
			}
			var fields = arrayOf(item, "fields");
			if (fields !== null) {
				for (var f = 0; f < fields.length; f++) {
					if (isObject(fields[f])) { entry.customFields.push({ name: trim(textOf(fields[f], "name")), value: textOf(fields[f], "value") }); }
				}
			}
			entry.name = textOf(item, "name");
			entry.notes = textOf(item, "notes");
			entry.favorite = isTrue(item, "favorite");
			var folderId = textOf(item, "folderId");
			entry.folder = folderNames.has(folderId) ? folderNames.get(folderId) : "";
			entries.push(entry);
		}
		return parsedImport("bitwarden_json", "Bitwarden (JSON)", entries, items.length, unsupported, inTrash, []);
	}

	// §6. BitosX's own export, read back.
	function readBitosXExport(root) {
		if (member(root, "version") !== 1) { throw new ImportRefused("unsupported_version"); }
		var items = arrayOf(root, "items");
		if (items === null) { throw new ImportRefused("not_recognised"); }
		if (items.length > MAX_ENTRIES) { throw new ImportRefused("too_many_entries"); }

		var entries = [];
		var unsupported = {};
		for (var index = 0; index < items.length; index++) {
			var item = items[index];
			if (!isObject(item) || textOf(item, "type") !== "login") { count(unsupported, "other"); continue; }
			var entry = importEntry(index + 1);
			entry.name = textOf(item, "name");
			entry.username = textOf(item, "username");
			entry.password = textOf(item, "password");
			entry.notes = textOf(item, "notes");
			entry.favorite = isTrue(item, "favorite");
			var urls = arrayOf(item, "urls");
			if (urls !== null) {
				for (var u = 0; u < urls.length; u++) { if (typeof urls[u] === "string") { entry.addresses.push(urls[u]); } }
			}
			entries.push(entry);
		}
		return parsedImport("bitosx_json", "BitosX (JSON)", entries, items.length, unsupported, 0, []);
	}

	// ---- §5 KeePass 2 XML ----
	// The browser's own XML parser reads the document; nothing here parses XML by hand. A document
	// type declaration is refused on the text itself, before the parser sees it, so there is never
	// an entity to expand or anything to fetch.
	var NO_UUID = "AAAAAAAAAAAAAAAAAAAAAA==";   // sixteen zero bytes: "no group"
	var PARSER_ERROR_NAMESPACES = ["http://www.w3.org/1999/xhtml", "http://www.mozilla.org/newlayout/xml/parsererror.xml"];
	var ELEMENT_NODE = 1, TEXT_NODE = 3, CDATA_SECTION_NODE = 4;

	// Whether the text contains "<!DOCTYPE" anywhere, in any letter case (A to Z only): also inside
	// a comment or a CDATA section, which no export contains.
	function containsDoctype(text) {
		for (var at = text.indexOf("<!"); at >= 0; at = text.indexOf("<!", at + 2)) {
			if (toLowerAscii(text.slice(at + 2, at + 9)) === "doctype") { return true; }
		}
		return false;
	}

	// A document the parser could not read holds a <parsererror> element in place of, or inside,
	// what it read (in the XHTML namespace in Chromium and Safari, in Mozilla's own in Firefox).
	function isParserErrorDocument(doc) {
		if (!doc || !doc.documentElement) { return true; }
		for (var i = 0; i < PARSER_ERROR_NAMESPACES.length; i++) {
			if (doc.getElementsByTagNameNS(PARSER_ERROR_NAMESPACES[i], "parsererror").length > 0) { return true; }
		}
		return false;
	}

	function readKeePassXml(text) {
		if (containsDoctype(text)) { throw new ImportRefused("doctype"); }
		if (typeof DOMParserCtor !== "function") { throw new XmlParserUnavailable(); }

		var doc;
		// Spaces, tabs and line ends before the first "<" are not part of the document.
		try { doc = new DOMParserCtor().parseFromString(text.slice(firstNonSpace(text)), "application/xml"); }
		catch (e) { throw new ImportRefused("invalid_xml"); }
		// The parser's message can quote the file, so it is not passed on.
		if (isParserErrorDocument(doc)) { throw new ImportRefused("invalid_xml"); }

		// The document is walked in the order it is written, and the first fault that is met decides
		// (§5.2). On every element, read or passed over: how deep it is, then whether it says that
		// its value is encrypted, then what it is.
		var entries = [];          // every Entry directly inside a Group, in document order
		var recycleBinUuid = null;
		var hasMeta = false, hasRoot = false;

		function check(element, level) {
			if (level > MAX_XML_DEPTH) { throw new ImportRefused("nested_too_deeply"); }
			var isProtected = element.getAttribute("Protected");
			if (isProtected !== null && (isProtected === "1" || toLowerAscii(isProtected) === "true")) {
				throw new ImportRefused("protected_values");
			}
		}
		// Calls onChild for every element directly inside `element`, after checking it.
		function forEachChild(element, level, onChild) {
			for (var node = element.firstChild; node !== null; node = node.nextSibling) {
				if (node.nodeType === ELEMENT_NODE) { check(node, level + 1); onChild(node, level + 1); }
			}
		}
		// Passes over an element and everything inside it, checking every element.
		function skip(element, level) { forEachChild(element, level, skip); }
		// The text of an element: its own text and CDATA sections, one after the other, exactly as
		// the parser delivers them. An element inside it is passed over.
		function readText(element, level) {
			var value = "";
			for (var node = element.firstChild; node !== null; node = node.nextSibling) {
				if (node.nodeType === TEXT_NODE || node.nodeType === CDATA_SECTION_NODE) { value += node.data; }
				else if (node.nodeType === ELEMENT_NODE) { check(node, level + 1); skip(node, level + 1); }
			}
			return value;
		}

		function readString(element, level, entry) {
			var key = null, value = null;
			forEachChild(element, level, function (child, childLevel) {
				if (child.nodeName === "Key" && key === null) { key = readText(child, childLevel); }
				else if (child.nodeName === "Value" && value === null) { value = readText(child, childLevel); }
				else { skip(child, childLevel); }
			});
			if (key === null) { return; }
			if (value === null) { value = ""; }
			var field = key === "Title" ? "title" : key === "UserName" ? "userName" : key === "Password" ? "password"
				: key === "URL" ? "url" : key === "Notes" ? "notes" : null;
			if (field === null) {
				// Every other string is a custom field: KeePass keeps authenticator keys in such
				// strings too ("otp", "TOTP Seed", "TimeOtp-Secret…"), under whatever name.
				entry.customFields.push({ name: trim(key), value: value });
			} else if (entry[field] !== null) {
				entry.hasFieldTwice = true;   // the first value is the one that is shown
			} else {
				entry[field] = value;
			}
		}
		function readEntry(element, level, group) {
			if (entries.length >= MAX_ENTRIES) { throw new ImportRefused("too_many_entries"); }
			var entry = { group: group, position: entries.length + 1, title: null, userName: null, password: null, url: null, notes: null, hasFieldTwice: false, customFields: [] };
			entries.push(entry);
			// Only the strings are read. The earlier versions of the entry are in History, which is
			// passed over like everything else, so they are neither imported nor counted.
			forEachChild(element, level, function (child, childLevel) {
				if (child.nodeName === "String") { readString(child, childLevel, entry); }
				else { skip(child, childLevel); }
			});
		}
		function readGroup(element, level, parent, groupLevel) {
			if (groupLevel > MAX_GROUP_DEPTH) { throw new ImportRefused("nested_too_deeply"); }
			var group = { parent: parent, uuid: null, name: null, inRecycleBin: null };
			forEachChild(element, level, function (child, childLevel) {
				var name = child.nodeName;
				if (name === "UUID" && group.uuid === null) { group.uuid = trim(readText(child, childLevel)); }
				else if (name === "Name" && group.name === null) { group.name = trim(readText(child, childLevel)); }
				else if (name === "Entry") { readEntry(child, childLevel, group); }
				else if (name === "Group") { readGroup(child, childLevel, group, groupLevel + 1); }
				else { skip(child, childLevel); }
			});
		}

		var rootElement = doc.documentElement;
		// An element is known by its name as written; namespaces mean nothing here.
		if (rootElement.nodeName !== "KeePassFile") { throw new ImportRefused("not_recognised"); }
		check(rootElement, 1);
		forEachChild(rootElement, 1, function (child, childLevel) {
			if (child.nodeName === "Meta" && !hasMeta) {
				hasMeta = true;
				forEachChild(child, childLevel, function (inMeta, metaLevel) {
					if (inMeta.nodeName === "RecycleBinUUID" && recycleBinUuid === null) { recycleBinUuid = trim(readText(inMeta, metaLevel)); }
					else { skip(inMeta, metaLevel); }
				});
			} else if (child.nodeName === "Root" && !hasRoot) {
				hasRoot = true;
				forEachChild(child, childLevel, function (inRoot, rootLevel) {
					if (inRoot.nodeName === "Group") { readGroup(inRoot, rootLevel, null, 1); }
					else { skip(inRoot, rootLevel); }
				});
			} else {
				skip(child, childLevel);
			}
		});

		// The recycle bin is the group the file names as such; what is in a group inside it is in it.
		function isInRecycleBin(group) {
			if (recycleBinUuid === null || recycleBinUuid.length === 0 || recycleBinUuid === NO_UUID) { return false; }
			if (group.inRecycleBin !== null) { return group.inRecycleBin; }
			group.inRecycleBin = group.uuid === recycleBinUuid || (group.parent !== null && isInRecycleBin(group.parent));
			return group.inRecycleBin;
		}
		// The names of the groups an entry is in, from the one below its root group down, with "/"
		// between them. The root group is the database itself and is left out; so is a group without a name.
		function pathOf(group) {
			var names = [];
			for (var g = group; g !== null && g.parent !== null; g = g.parent) {
				if (g.name !== null && g.name.length > 0) { names.push(g.name); }
			}
			return names.reverse().join("/");
		}

		var result = [];
		var inTrash = 0;
		entries.forEach(function (found) {
			if (isInRecycleBin(found.group)) { inTrash++; return; }
			var entry = importEntry(found.position);
			entry.name = found.title === null ? "" : found.title;
			entry.username = found.userName === null ? "" : found.userName;
			entry.password = found.password === null ? "" : found.password;
			entry.notes = found.notes === null ? "" : found.notes;
			entry.addresses = found.url !== null && found.url.length > 0 ? [found.url] : [];
			entry.folder = pathOf(found.group);
			entry.customFields = found.customFields;
			entry.problem = found.hasFieldTwice ? "field_twice" : null;
			result.push(entry);
		});
		return parsedImport("keepass_xml", "KeePass 2 (XML)", result, entries.length, {}, inTrash, []);
	}

	// ---- §2 the entry point: bytes in, the logins of the file out ----
	// The format is detected from the content, never from a file name: the first character that is
	// not a space, a tab or a line end decides. Throws ImportRefused for a file that is not read.
	function parseImport(bytes) {
		var text = decodeFile(bytes);
		var first = firstNonSpace(text);
		if (first < 0) { throw new ImportRefused("empty"); }
		var c = text.charAt(first);
		if (c === "{" || c === "[") { return readJson(text); }
		if (c === "<") { return readKeePassXml(text); }
		return readCsv(text);
	}

	// ---- §7.2, §7.3 addresses, as exact patterns with a plainly linear cost ----
	var ADDRESS_WEB = "web", ADDRESS_HOST = "host", ADDRESS_OTHER = "other";

	// The length of the scheme the value starts with, if "://" follows it: ^[A-Za-z][A-Za-z0-9+.-]*://
	function schemeLength(value) {
		if (value.length === 0 || !isAsciiLetterCode(value.charCodeAt(0))) { return 0; }
		var i = 1;
		while (i < value.length) {
			var c = value.charCodeAt(i);
			if (!isAsciiLetterOrDigitCode(c) && c !== 0x2B && c !== 0x2E && c !== 0x2D) { break; }
			i++;
		}
		return value.startsWith("://", i) ? i : 0;
	}
	// LABEL = [A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?   between `from` and `to`
	function isLabel(text, from, to) {
		if (to <= from || !isAsciiLetterOrDigitCode(text.charCodeAt(from)) || !isAsciiLetterOrDigitCode(text.charCodeAt(to - 1))) { return false; }
		for (var i = from; i < to; i++) {
			var c = text.charCodeAt(i);
			if (!isAsciiLetterOrDigitCode(c) && c !== 0x2D) { return false; }
		}
		return true;
	}
	// DOMAIN = (?:LABEL\.)+TLD, TLD a label that starts with a letter: a name needs a dot.
	function isDomain(host) {
		var labels = 0, from = 0;
		for (;;) {
			var dot = host.indexOf(".", from);
			var to = dot < 0 ? host.length : dot;
			if (!isLabel(host, from, to)) { return false; }
			labels++;
			if (dot < 0) { return labels >= 2 && isAsciiLetterCode(host.charCodeAt(from)); }
			from = dot + 1;
		}
	}
	// OCTET = 25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]: 0 to 255, in decimal, without a leading zero.
	function isOctet(text, from, to) {
		var length = to - from;
		if (length < 1 || length > 3) { return false; }
		var value = 0;
		for (var i = from; i < to; i++) {
			var c = text.charCodeAt(i);
			if (!isAsciiDigitCode(c)) { return false; }
			value = value * 10 + (c - 0x30);
		}
		if (length > 1 && text.charCodeAt(from) === 0x30) { return false; }
		return value <= 255;
	}
	// IPV4 = OCTET(?:\.OCTET){3}
	function isIPv4(host) {
		var from = 0;
		for (var part = 1; part <= 4; part++) {
			var dot = host.indexOf(".", from);
			if ((dot < 0) !== (part === 4)) { return false; }
			if (!isOctet(host, from, dot < 0 ? host.length : dot)) { return false; }
			from = dot + 1;
		}
		return true;
	}
	// ^(?:DOMAIN|IPV4)(?::[0-9]{1,5})?(?:[/?#][\s\S]*)?$
	function looksLikeHost(value) {
		var hostEnd = indexOfAny(value, ":/?#");
		if (hostEnd < 0) { hostEnd = value.length; }
		var host = value.slice(0, hostEnd);
		if (!isDomain(host) && !isIPv4(host)) { return false; }
		var i = hostEnd;
		if (i < value.length && value.charAt(i) === ":") {
			var digits = 0;
			i++;
			while (i < value.length && isAsciiDigitCode(value.charCodeAt(i))) { i++; digits++; }
			if (digits < 1 || digits > 5) { return false; }
		}
		return i === value.length || "/?#".indexOf(value.charAt(i)) >= 0;
	}
	// What an address value is taken to be. It has been trimmed, is not empty, and holds no line end.
	function classifyAddress(value) {
		if (hasControlCharacter(value)) { return ADDRESS_OTHER; }
		var scheme = schemeLength(value);
		if (scheme > 0) {
			var name = toLowerAscii(value.slice(0, scheme));
			return name === "http" || name === "https" ? ADDRESS_WEB : ADDRESS_OTHER;
		}
		return looksLikeHost(value) ? ADDRESS_HOST : ADDRESS_OTHER;
	}

	// All digits, or 0x and hexadecimal digits: what a browser takes for part of an IPv4 address.
	function looksLikeANumber(part) {
		if (part.length === 0) { return false; }
		if (allDigits(part)) { return true; }
		if (part.length < 2 || part.charAt(0) !== "0" || (part.charAt(1) !== "x" && part.charAt(1) !== "X")) { return false; }
		for (var i = 2; i < part.length; i++) { if (!isHexDigitCode(part.charCodeAt(i))) { return false; } }
		return true;
	}
	// The part of a web address between "://" and the next "/", "?" or "#" (a backslash does not end it).
	function authorityOf(webAddress) {
		var start = webAddress.indexOf("://");
		if (start < 0) { return null; }
		var end = indexOfAny(webAddress, "/?#", start + 3);
		return webAddress.slice(start + 3, end < 0 ? webAddress.length : end);
	}
	// §7.3: whether the host of a web address is one both clients read the same way. The vault's
	// own rule for an address is each client's own (here: new URL), and the two differ about unusual
	// hosts; an import asks this first, so that an entry is imported by both clients or by neither.
	function hasPlausibleHost(webAddress) {
		var authority = authorityOf(webAddress);
		if (authority === null) { return false; }
		var at = authority.indexOf("@");
		if (at >= 0) {
			authority = authority.slice(at + 1);
			if (authority.indexOf("@") >= 0) { return false; }
		}
		var i;
		if (authority.charAt(0) === "[") {
			var close = authority.indexOf("]");
			if (close < 2) { return false; }
			for (i = 1; i < close; i++) {
				var b = authority.charCodeAt(i);
				if (!isHexDigitCode(b) && b !== 0x3A && b !== 0x2E) { return false; }
			}
			return close + 1 === authority.length || (authority.charAt(close + 1) === ":" && allDigits(authority, close + 2));
		}
		var host = authority;
		var colon = authority.indexOf(":");
		if (colon >= 0) {
			if (!allDigits(authority, colon + 1)) { return false; }
			host = authority.slice(0, colon);
		}
		if (host.length === 0 || host.charAt(0) === "." || host.indexOf("..") >= 0) { return false; }
		for (i = 0; i < host.length; i++) {
			var c = host.charCodeAt(i);
			if (c < 0x80 && !isAsciiLetterOrDigitCode(c) && c !== 0x2D && c !== 0x2E && c !== 0x5F) { return false; }
		}
		var withoutLastDot = host.charAt(host.length - 1) === "." ? host.slice(0, -1) : host;
		var lastPart = withoutLastDot.slice(withoutLastDot.lastIndexOf(".") + 1);
		return !looksLikeANumber(lastPart) || isIPv4(withoutLastDot);
	}
	// §7.5: the host of a web address, for the name of an entry that has none. Taken from the text;
	// the address is not handed to a URL parser, so that both clients arrive at the same name.
	function hostOf(webAddress) {
		var authority = authorityOf(webAddress);
		if (authority === null) { return ""; }
		var at = authority.lastIndexOf("@");
		if (at >= 0) { authority = authority.slice(at + 1); }
		var host = authority;
		if (authority.charAt(0) === "[") {
			var close = authority.indexOf("]");   // an IPv6 address: everything up to its closing bracket
			if (close >= 0) { host = authority.slice(0, close + 1); }
		} else {
			var colon = authority.lastIndexOf(":");
			if (colon >= 0 && allDigits(authority, colon + 1)) { host = authority.slice(0, colon); }
		}
		return toLowerAscii(host);
	}

	// ---- §7 from an entry to an item ----
	function deriveName(urls, username) {
		if (urls.length > 0) {
			var host = trim(hostOf(urls[0]));
			if (host.length > 0 && host.length <= ITEM.name) { return host; }
		}
		var fromUsername = trim(username);
		return fromUsername.length > 0 && fromUsername.length <= ITEM.name ? fromUsername : TEXTS.untitledName;
	}
	// §7.6: the first limit of the vault the entry breaks, in this order, or null.
	function checkLimits(name, entry, urls) {
		if (name.length > ITEM.name) { return "name_too_long"; }
		if (entry.username.length > ITEM.username) { return "username_too_long"; }
		if (entry.password.length > ITEM.password) { return "password_too_long"; }
		if (entry.notes.length > ITEM.notes) { return "notes_too_long"; }
		if (urls.length > ITEM.urls) { return "too_many_urls"; }
		var i;
		for (i = 0; i < urls.length; i++) { if (urls[i].length > ITEM.url) { return "url_too_long"; } }
		// First the rule both clients share, then the vault's own.
		for (i = 0; i < urls.length; i++) { if (!hasPlausibleHost(urls[i]) || !vc.isValidUrl(urls[i])) { return "url_invalid"; } }
		return null;
	}
	// §7.4: the notes with the extras after them, one on each line with a label. An empty line
	// stands between the notes of the file and the first of them.
	function withExtras(notes, extras) {
		var lines = [];
		if (extras.totp.length > 0) { lines.push(NOTES_LABEL_TOTP + ": " + extras.totp); }
		if (extras.folder.length > 0) { lines.push(NOTES_LABEL_FOLDER + ": " + extras.folder); }
		extras.otherAddresses.forEach(function (address) { lines.push(NOTES_LABEL_OTHER_ADDRESS + ": " + address); });
		extras.customFields.forEach(function (field) { lines.push((field.name.length > 0 ? field.name : NOTES_LABEL_NAMELESS_FIELD) + ": " + field.value); });
		if (lines.length === 0) { return notes; }
		return (notes.length > 0 ? notes + "\n\n" : "") + lines.join("\n");
	}

	// Turns an entry as a file holds it into the item it would be stored as, with the reason it
	// cannot be stored if it cannot. Nothing is ever cut short to make it fit. Returns null for an
	// entry with nothing in it, which is counted and otherwise passed over.
	function normalizeEntry(entry, copyExtrasToNotes) {
		var name = trim(entry.name);

		// One value may hold several addresses, one on each line. Each is trimmed, empty ones are
		// dropped, and each is then a web address, a host to put https:// in front of, or neither.
		var urls = [], otherAddresses = [], httpsAdded = 0;
		entry.addresses.forEach(function (value) {
			splitLines(value).forEach(function (line) {
				var address = trim(line);
				if (address.length === 0) { return; }
				var kind = classifyAddress(address);
				if (kind === ADDRESS_WEB) { urls.push(address); }
				else if (kind === ADDRESS_HOST) { urls.push("https://" + address); httpsAdded++; }
				else { otherAddresses.push(address); }
			});
		});

		// A custom field without a value has nothing that could be lost.
		var customFields = entry.customFields.filter(function (field) { return !isBlank(field.value); });
		var extras = { totp: trim(entry.totp), folder: trim(entry.folder), otherAddresses: otherAddresses, customFields: customFields };

		if (name.length === 0 && urls.length === 0
			&& extras.totp.length === 0 && otherAddresses.length === 0 && customFields.length === 0
			&& isBlank(entry.username) && isBlank(entry.password) && isBlank(entry.notes)) {
			return null;   // nothing but, at most, the name of a folder
		}

		var nameWasDerived = false;
		if (name.length === 0) {
			name = deriveName(urls, entry.username);
			nameWasDerived = true;
		}

		var reason = entry.problem !== null ? entry.problem : checkLimits(name, entry, urls);
		var notes = entry.notes;
		if (copyExtrasToNotes) {
			notes = withExtras(notes, extras);
			if (reason === null && notes.length > ITEM.notes) { reason = "notes_too_long_with_extras"; }
		}

		return {
			position: entry.position,
			status: reason === null ? "add" : "not_imported",
			duplicate: false,
			reason: reason,
			name: name,
			username: entry.username,
			password: entry.password,
			urls: urls,
			notes: notes,
			favorite: entry.favorite,
			nameWasDerived: nameWasDerived,
			httpsAdded: httpsAdded,
			extras: extras
		};
	}

	// ---- §8, §9 the plan: what importing a file into a vault would do ----
	// The four values a duplicate is told by as one string that no other four values give: each one
	// preceded by its length, so that no character has to serve as a separator.
	function duplicateKey(name, username, password, urls) {
		var key = name.length + ":" + name + username.length + ":" + username + password.length + ":" + password + urls.length + ":";
		for (var i = 0; i < urls.length; i++) { key += urls[i].length + ":" + urls[i]; }
		return key;
	}

	// Compares the logins of a parsed file with the items of a vault and decides what becomes of
	// each. Changes nothing. vaultItems: the vault's items ({ name, username, password, urls }; a
	// value that is absent equals an empty one). options: { copyExtrasToNotes, importDuplicates },
	// both off unless chosen.
	function planImport(parsed, vaultItems, options) {
		var copyExtrasToNotes = !!(options && options.copyExtrasToNotes);
		var importDuplicates = !!(options && options.importDuplicates);

		var seen = new Set();
		vaultItems.forEach(function (item) {
			// Names and addresses of the vault's items are trimmed for the comparison, as those of the file are.
			seen.add(duplicateKey(trim(item.name), item.username == null ? "" : item.username, item.password == null ? "" : item.password, item.urls.map(trim)));
		});

		var candidates = [];
		var counts = {
			toAdd: 0, duplicates: 0, notImported: 0, empty: 0, httpsAdded: 0, namesDerived: 0,
			vaultItemsBefore: vaultItems.length, vaultItemsAfter: 0, exceedsVaultItemLimit: false
		};
		var extras = {};
		parsed.entries.forEach(function (entry) {
			var candidate = normalizeEntry(entry, copyExtrasToNotes);
			if (candidate === null) { counts.empty++; return; }
			// An entry that is not imported is nobody's duplicate, and nothing is a duplicate of it.
			if (candidate.status === "add") {
				var key = duplicateKey(candidate.name, candidate.username, candidate.password, candidate.urls);
				if (seen.has(key)) {
					candidate.duplicate = true;
					counts.duplicates++;
					if (!importDuplicates) { candidate.status = "duplicate"; }
				} else {
					seen.add(key);
				}
			}
			if (candidate.status === "not_imported") { counts.notImported++; }
			if (candidate.status === "add") {
				// Extras, added https:// and derived names are counted over the entries that will be added.
				counts.toAdd++;
				counts.httpsAdded += candidate.httpsAdded;
				if (candidate.nameWasDerived) { counts.namesDerived++; }
				if (candidate.extras.totp.length > 0) { count(extras, "totp"); }
				if (candidate.extras.folder.length > 0) { count(extras, "folder"); }
				extras.other_address = (extras.other_address || 0) + candidate.extras.otherAddresses.length;
				extras.custom_field = (extras.custom_field || 0) + candidate.extras.customFields.length;
			}
			candidates.push(candidate);
		});
		counts.vaultItemsAfter = counts.vaultItemsBefore + counts.toAdd;
		counts.exceedsVaultItemLimit = counts.vaultItemsAfter > MAX_VAULT_ITEMS;

		return {
			format: parsed.format,
			label: parsed.label,
			records: parsed.records,
			unsupported: parsed.unsupported,
			inTrash: parsed.inTrash,
			ignoredColumns: parsed.ignoredColumns,
			options: { copyExtrasToNotes: copyExtrasToNotes, importDuplicates: importDuplicates },
			counts: counts,
			extras: countsInOrder(extras, EXTRA_ORDER),
			candidates: candidates
		};
	}

	// A copy of a string that shares nothing with the text it was cut from. A JavaScript engine may
	// keep a whole file's text alive for as long as one short piece of it lives; the items of the
	// vault outlive the import, and must not do that to the file.
	var copyEncoder = new TextEncoder();
	var copyDecoder = new TextDecoder("utf-8", { ignoreBOM: true });
	function detached(text) { return copyDecoder.decode(copyEncoder.encode(text)); }

	// The items a plan adds, in the order of the file, as the vault holds items: each with a new
	// identifier (never one from the file), created and last changed at `now`. An empty username,
	// password or notes is stored the way the editor stores it, as none. Throws ImportRefused
	// (vault_item_limit) for a plan that would pass the limit on a vault: never applied in part.
	function createItems(plan, now) {
		if (plan.counts.exceedsVaultItemLimit) { throw new ImportRefused("vault_item_limit"); }
		var items = [];
		plan.candidates.forEach(function (candidate) {
			if (candidate.status !== "add") { return; }
			items.push(Object.freeze({
				id: vc.newId(),
				type: "login",
				name: detached(candidate.name),
				username: candidate.username.length > 0 ? detached(candidate.username) : null,
				password: candidate.password.length > 0 ? detached(candidate.password) : null,
				urls: Object.freeze(candidate.urls.map(detached)),
				notes: candidate.notes.length > 0 ? detached(candidate.notes) : null,
				favorite: candidate.favorite === true,
				createdAt: now,
				createdAtText: null,
				updatedAt: now
			}));
		});
		return items;
	}

	// ---- reading the file the person chose ----
	// The size is looked at before anything is read (§1), never more than the limit and one byte is
	// read, and the bytes that were read are counted again. Resolves to the bytes; rejects with
	// ImportRefused (too_large), or with whatever the browser says when it cannot read the file.
	function readFileBytes(file) {
		return Promise.resolve().then(function () {
			if (!file || typeof file.size !== "number" || typeof file.slice !== "function") { throw new TypeError("Not a file."); }
			if (file.size > MAX_FILE_BYTES) { throw new ImportRefused("too_large"); }
			var part = file.slice(0, MAX_FILE_BYTES + 1);
			if (typeof part.arrayBuffer === "function") { return part.arrayBuffer(); }
			return new Promise(function (resolve, reject) {
				var reader = new FileReader();
				reader.onload = function () { resolve(reader.result); };
				reader.onerror = function () { reject(reader.error || new Error("The file could not be read.")); };
				reader.readAsArrayBuffer(part);
			});
		}).then(function (buffer) {
			var bytes = new Uint8Array(buffer);
			if (bytes.length > MAX_FILE_BYTES) { throw new ImportRefused("too_large"); }
			return bytes;
		});
	}

	// ---- §11 export: two formats, both unencrypted, values exactly as they are ----
	// Nothing is put in front of a value that a spreadsheet program would take for a formula
	// (§11.3): the file is there to be read by another password manager, and a password with a quote
	// mark in front of it is another password. The person is told not to open it in such a program.
	var EXPORT_CSV = "csv", EXPORT_JSON = "json";
	var utf8Encoder = new TextEncoder();

	// Text that is not valid Unicode (half of a surrogate pair) is written as U+FFFD.
	function wellFormed(text) {
		if (typeof text.toWellFormed === "function") { return text.toWellFormed(); }
		var out = "";
		for (var i = 0; i < text.length; i++) {
			var c = text.charCodeAt(i);
			if (c >= 0xD800 && c <= 0xDBFF && i + 1 < text.length && text.charCodeAt(i + 1) >= 0xDC00 && text.charCodeAt(i + 1) <= 0xDFFF) {
				out += text.charAt(i) + text.charAt(i + 1);
				i++;
			} else {
				out += c >= 0xD800 && c <= 0xDFFF ? "�" : text.charAt(i);
			}
		}
		return out;
	}
	function csvValue(value) { return "\"" + wellFormed(value).replace(/"/g, "\"\"") + "\""; }

	// §11.1: Chrome's layout. UTF-8 without a byte order mark; the header line not quoted; then one
	// line for each item, every value in double quotes with a double quote inside it written twice;
	// CR LF after every line, the last one included. url is the item's first address.
	function exportCsv(items) {
		var lines = ["name,url,username,password,note\r\n"];
		items.forEach(function (item) {
			lines.push(csvValue(item.name) + "," + csvValue(item.urls.length > 0 ? item.urls[0] : "") + ","
				+ csvValue(item.username == null ? "" : item.username) + "," + csvValue(item.password == null ? "" : item.password) + ","
				+ csvValue(item.notes == null ? "" : item.notes) + "\r\n");
		});
		return utf8Encoder.encode(lines.join(""));
	}

	// A time as the export writes it: UTC, ending in Z. An item's times keep their fraction of a
	// second, up to seven digits, without trailing zeros; the desktop writes seven where a Date
	// keeps three, so the text the vault held is used while it still says the same instant.
	var DATE_TEXT_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})$/;
	function itemTimestamp(date, text) {
		var fraction = null, whole = date;
		var m = typeof text === "string" ? DATE_TEXT_RE.exec(text) : null;
		if (m && new Date(text).getTime() === date.getTime()) {
			var second = new Date(m[1] + m[3]);   // the same instant without its fraction: nothing to round
			if (!isNaN(second.getTime())) { whole = second; fraction = m[2] || ""; }
		}
		var iso = whole.toISOString();           // 2026-11-10T12:00:00.000Z
		if (fraction === null) { fraction = iso.slice(20, 23); }
		fraction = fraction.replace(/0+$/, "");
		return iso.slice(0, 19) + (fraction.length > 0 ? "." + fraction : "") + "Z";
	}

	// §11.2: BitosX's own export. Everything a vault holds is in it; a value an item does not have
	// is the empty string. Indented by two spaces, LF line ends and one at the end (none of which
	// is part of the format).
	function exportJson(items, exportedAt) {
		var doc = {
			format: "bitosx-export",
			version: 1,
			exportedAt: exportedAt.toISOString().slice(0, 19) + "Z",
			items: items.map(function (item) {
				return {
					type: "login",
					name: wellFormed(item.name),
					username: wellFormed(item.username == null ? "" : item.username),
					password: wellFormed(item.password == null ? "" : item.password),
					urls: item.urls.map(wellFormed),
					notes: wellFormed(item.notes == null ? "" : item.notes),
					favorite: item.favorite === true,
					createdAt: itemTimestamp(item.createdAt, item.createdAtText),
					updatedAt: itemTimestamp(item.updatedAt, item.updatedAtText)
				};
			})
		};
		return utf8Encoder.encode(JSON.stringify(doc, null, 2) + "\n");
	}

	// The items of a vault as the bytes of an export file. format: "csv" or "json".
	function exportVault(items, format, exportedAt) {
		if (format === EXPORT_CSV) { return exportCsv(items); }
		if (format === EXPORT_JSON) { return exportJson(items, exportedAt); }
		throw new RangeError("Unknown export format.");
	}

	// How many items have more than one address. A CSV export holds only the first of each: this is
	// the number a person is told before choosing it.
	function countItemsWithSeveralUrls(items) {
		var n = 0;
		items.forEach(function (item) { if (item.urls.length > 1) { n++; } });
		return n;
	}

	// BitosX-export-YYYY-MM-DD.csv or .json, with the local date of `now`.
	function exportFileName(format, now) {
		if (format !== EXPORT_CSV && format !== EXPORT_JSON) { throw new RangeError("Unknown export format."); }
		function two(n) { return (n < 10 ? "0" : "") + n; }
		return "BitosX-export-" + now.getFullYear() + "-" + two(now.getMonth() + 1) + "-" + two(now.getDate()) + "." + format;
	}

	return Object.freeze({
		ImportRefused: ImportRefused,
		XmlParserUnavailable: XmlParserUnavailable,
		LIMITS: Object.freeze({
			maxFileBytes: MAX_FILE_BYTES, maxEntries: MAX_ENTRIES, maxVaultItems: MAX_VAULT_ITEMS,
			maxJsonDepth: MAX_JSON_DEPTH, maxGroupDepth: MAX_GROUP_DEPTH, maxXmlDepth: MAX_XML_DEPTH
		}),
		REFUSAL_TEXTS: REFUSAL_TEXTS,
		REASON_TEXTS: REASON_TEXTS,
		EXTRA_TEXTS: EXTRA_TEXTS,
		UNSUPPORTED_TEXTS: UNSUPPORTED_TEXTS,
		TEXTS: TEXTS,
		readFileBytes: readFileBytes,
		parseImport: parseImport,
		planImport: planImport,
		createItems: createItems,
		EXPORT_CSV: EXPORT_CSV,
		EXPORT_JSON: EXPORT_JSON,
		exportVault: exportVault,
		exportCsv: exportCsv,
		exportJson: exportJson,
		countItemsWithSeveralUrls: countItemsWithSeveralUrls,
		exportFileName: exportFileName,
		// The parts, for the unit tests.
		_trim: trim,
		_isBlank: isBlank,
		_toLowerAscii: toLowerAscii,
		_splitLines: splitLines,
		_hasControlCharacter: hasControlCharacter,
		_decodeFile: decodeFile,
		_CsvRecordReader: CsvRecordReader,
		_checkJsonText: checkJsonText,
		_parseJsonStrict: parseJsonStrict,
		_containsDoctype: containsDoctype,
		_classifyAddress: classifyAddress,
		_looksLikeHost: looksLikeHost,
		_hasPlausibleHost: hasPlausibleHost,
		_hostOf: hostOf,
		_normalizeEntry: normalizeEntry,
		_itemTimestamp: itemTimestamp,
		_wellFormed: wellFormed
	});
});
