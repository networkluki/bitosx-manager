// The vault panel (vault.bitosx.se): read and edit the vault in the browser.
//
// The server holds the vault as the encrypted file the desktop app uploaded and cannot open it.
// This page downloads those bytes, checks them against what the server states about them, and
// opens them here with the master password — Argon2id and AES-256-GCM exactly as the desktop does
// it (vault-crypto.js). The master password and the decrypted items exist only in this script's
// memory, only while unlocked; nothing is written anywhere, and nothing decrypted is ever sent.
// Changes are encrypted in the browser under the same vault key (fresh nonce,
// VaultCryptor.ReEncryptContent) and uploaded only on "Save to server", with the same
// compare-and-set rule the desktop uses — if another device changed the vault on the server first,
// nothing is overwritten and the user chooses.
(function () {
	"use strict";

	var api = window.bitosxApi;
	var ui = window.bitosxUi;
	var cfg = window.BITOSX_CONFIG;
	var vc = window.bitosxVaultCrypto;
	var $ = ui.$;

	var panel = $("vault-panel");
	if (!panel) { return; }
	var notice = $("vault-notice");
	var statusText = $("vault-status-text");
	var unlockForm = $("vault-unlock-form");
	var passwordEl = $("vault-master-password");
	var progress = $("vault-progress");
	var itemsSection = $("vault-items-section");
	var itemsList = $("vault-items");
	var searchEl = $("vault-search");
	var favoritesEl = $("vault-favorites");
	var sortEl = $("vault-sort");
	var countEl = $("vault-count");
	var backupButton = $("vault-backup");

	var server = null;      // what the server holds (public metadata), or null
	// While unlocked: { items, vaultKey, envelope, revision, dirty, changes } — the only copy of the
	// decrypted vault and of the vault key. Both exist only here, only until lock. items are kept in
	// the order the vault stores them (the desktop's order); the list is sorted only for display.
	var opened = null;
	var busy = false;
	var backupBusy = false;
	var editing = null;     // the id of the item in the editor, or "" for a new one, or null when closed
	var editorSnapshot = null;
	// Changes whenever the vault locks; an unlock or upload that finishes after that is dropped.
	var epoch = 0;
	// An upload whose answer never arrived: if the server holds exactly these bytes, it arrived.
	var uncertainUpload = null; // { opened, fingerprint, next, changes }

	var editor = $("vault-editor");
	var editorNotice = $("vault-editor-notice");
	var dirtyNote = $("vault-dirty");
	var saveButton = $("vault-save");
	var conflictPanel = $("vault-conflict");
	var conflictText = $("vault-conflict-text");
	var overwriteRow = $("vault-overwrite-row");
	var overwriteAck = $("vault-overwrite-ack");
	var overwriteButton = $("vault-overwrite");

	function generation() { return api.generation(); }

	// The inline note states the configured times, not copies of them.
	$("note-clipboard-seconds").textContent = String(Math.round(cfg.clipboardClearMs / 1000));
	$("note-vault-minutes").textContent = String(Math.round(cfg.vaultIdleTimeoutMs / 60000));

	// ---- showing state ----
	function setStatus(text) { statusText.textContent = text; }

	function formatSize(bytes) {
		if (bytes < 1024) { return bytes + " bytes"; }
		if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(1) + " KiB"; }
		return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
	}
	function describeServer(s) {
		return "Encrypted vault on the server: revision " + s.revision + ", " + formatSize(s.sizeBytes) + ", stored " + ui.formatDate(s.updatedAt) + ".";
	}

	function showLocked() {
		epoch++;
		if (opened && opened.vaultKey) { opened.vaultKey.fill(0); }
		opened = null;
		uncertainUpload = null;
		clearIdle();
		closeEditor();
		hideConflict();
		ui.clear(itemsList);
		countEl.textContent = "";
		searchEl.value = "";
		favoritesEl.checked = false;
		itemsSection.hidden = true;
		unlockForm.hidden = server === null;
		backupButton.hidden = server === null;
		passwordEl.value = "";
		progress.textContent = "";
		setDirty(false);
	}

	function setDirty(value) {
		if (opened) { opened.dirty = value; }
		dirtyNote.hidden = !value;
		saveButton.disabled = !value || busy;
	}

	function markChanged() {
		opened.changes++;
		setDirty(true);
	}

	function hideConflict() {
		conflictPanel.hidden = true;
		overwriteRow.hidden = false;
		overwriteAck.checked = false;
		overwriteButton.disabled = true;
	}

	function hasUnsavedChanges() { return opened !== null && (opened.dirty || editorModified()); }

	// keepClipboard: the tab was hidden — most likely to paste what was just copied, so the
	// clipboard is left to its timer. Every other lock takes a copied secret with it, when the
	// browser allows it (the clear is retried when the page has focus again otherwise).
	function lock(message, keepClipboard) {
		var had = opened !== null;
		showLocked();
		if (!keepClipboard) { ui.clearClipboard(true); }
		if (had) { ui.notice(notice, "ok", message || "Vault locked."); }
	}

	function hidePanel() {
		lock();
		server = null;
		panel.hidden = true;
		backupButton.hidden = true;
		ui.notice(notice, "ok", "");
	}

	// ---- idle lock (separate from, and shorter than, the account sign-out) ----
	// A timer, plus the wall clock: timers stall in background tabs and while the computer sleeps.
	var idleTimer = null;
	var lastActivity = 0;
	var idleWarned = false;
	function clearIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } idleWarned = false; }
	function armIdle() {
		if (idleTimer) { clearTimeout(idleTimer); }
		var idle = Date.now() - lastActivity;
		var warnAt = cfg.vaultIdleTimeoutMs - cfg.idleWarningMs;
		var next = idle < warnAt ? warnAt - idle : cfg.vaultIdleTimeoutMs - idle;
		idleTimer = setTimeout(checkIdle, Math.max(next, 0));
	}
	function checkIdle() {
		if (!opened) { return; }
		var idle = Date.now() - lastActivity;
		if (idle >= cfg.vaultIdleTimeoutMs) {
			var unsaved = hasUnsavedChanges();
			lock("Vault locked after " + Math.round(cfg.vaultIdleTimeoutMs / 60000) + " minutes without activity." +
				(unsaved ? " Your unsaved changes were discarded." : ""));
			return;
		}
		if (idle >= cfg.vaultIdleTimeoutMs - cfg.idleWarningMs && hasUnsavedChanges() && !idleWarned) {
			idleWarned = true;
			ui.notice(notice, "warn", "Unsaved changes: without activity the vault locks in " + Math.round(cfg.idleWarningMs / 1000) +
				" seconds and they are discarded. Press Save to server to keep them.");
		}
		armIdle();
	}
	function noteActivity() {
		if (!opened) { return; }
		if (Date.now() - lastActivity >= cfg.vaultIdleTimeoutMs) { checkIdle(); return; } // time already ran out
		lastActivity = Date.now();
		if (idleWarned) { idleWarned = false; ui.notice(notice, "ok", ""); }
		armIdle();
	}
	// User input only: "scroll" also fires when the layout changes (an editor closing), which is not activity.
	["pointerdown", "keydown", "wheel", "touchstart", "input"].forEach(function (evt) {
		document.addEventListener(evt, noteActivity, { passive: true, capture: true });
	});
	setInterval(checkIdle, cfg.idleCheckIntervalMs);
	window.addEventListener("focus", checkIdle);
	window.addEventListener("pageshow", checkIdle);
	window.addEventListener("pagehide", function () { lock(); });
	window.addEventListener("beforeunload", function (ev) {
		// Unsaved changes exist only in this page; leaving discards them. The browser shows its own prompt.
		if (hasUnsavedChanges()) { ev.preventDefault(); ev.returnValue = ""; }
	});
	document.addEventListener("visibilitychange", function () {
		if (document.visibilityState === "visible") { checkIdle(); return; }
		// A hidden tab is an unattended screen: lock, as the desktop does on workstation lock —
		// unless there are unsaved changes (also typed into the editor), which a lock would discard;
		// the idle lock still applies.
		if (opened && !hasUnsavedChanges()) { lock("Vault locked when the tab was hidden.", true); }
	});

	// ---- what the server holds ----
	function loadStatus() {
		var g = generation();
		panel.hidden = false;
		ui.notice(notice, "ok", "");
		setStatus("Checking what the server holds…");
		return api.syncStatus()
			.then(function (status) {
				if (g !== generation()) { return; }
				server = status;
				if (!status) {
					setStatus("The server holds no vault for this account yet. Sync from the desktop app (Account → Sync now) and it appears here.");
				} else {
					setStatus(describeServer(status) + " Enter the vault's master password to read it in this browser.");
				}
				showLocked();
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				server = null;
				showLocked();
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; } // the account page shows the sign-in
				setStatus("");
				ui.notice(notice, "err", ui.describeError(err, "vault"));
			});
	}

	// ---- unlocking ----
	function describeVaultError(err) {
		var kind = err && err.kind;
		if (err instanceof api.ApiError) { return ui.describeError(err, "vault"); }
		switch (kind) {
			case vc.KINDS.AUTH: return "The master password is incorrect, or the vault on the server was modified. Nothing was opened.";
			case vc.KINDS.FORMAT: return "The vault on the server is not a vault this version of the web app can read.";
			case vc.KINDS.CONTENT: return "The vault opened, but its contents are not something this version understands. Nothing is shown.";
			case vc.KINDS.RESOURCE: return "This browser could not provide the memory the vault's key derivation needs. Try the desktop app, or a browser with more memory available.";
			default: return "The vault could not be opened. Nothing was changed.";
		}
	}

	function wipeUnlockResult(result) {
		if (result && result.plaintext) { result.plaintext.fill(0); }
		if (result && result.vaultKey) { result.vaultKey.fill(0); }
	}

	// The server no longer holds a vault (another device removed it): say so, and show what it holds.
	function vaultRemoved() {
		return loadStatus().then(function () {
			ui.notice(notice, "warn", "The server no longer holds a vault for this account; it was removed, probably from another device.");
		});
	}
	var REMOVED = { removed: true };

	unlockForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		if (busy || !server) { return; }
		var typed = passwordEl.value;
		if (typed.length === 0) {
			ui.markField(passwordEl, true, notice);
			ui.notice(notice, "err", "Enter the master password of your vault.");
			return;
		}
		busy = true;
		var myEpoch = epoch;
		var g = generation();
		function stale() { return myEpoch !== epoch || g !== generation(); }
		var parsedEnvelope = null;
		var download = null;
		ui.markField(passwordEl, false);
		ui.notice(notice, "ok", "");
		ui.setBusy(unlockForm, true);
		progress.textContent = "Downloading the encrypted vault…";

		api.syncEnvelope()
			.then(function (d) {
				if (!d) { throw REMOVED; }
				download = d;
				// The server's own statements about the bytes must hold for the bytes it sent.
				return vc.sha256Hex(d.envelope).then(function (hex) {
					if (hex !== d.fingerprint || d.envelope.length !== d.sizeBytes) {
						throw new api.ApiError(api.KINDS.UNEXPECTED, 200);
					}
					return vc.parseEnvelope(d.envelope);
				});
			})
			.then(function (envelope) {
				if (stale()) { throw REMOVED; }
				parsedEnvelope = envelope;
				var p = envelope.kdfParameters;
				progress.textContent = "Deriving the key: Argon2id with " + Math.round(p.memoryKiB / 1024) + " MiB, " + p.iterations
					+ " pass" + (p.iterations === 1 ? "" : "es") + ". In a browser this can take a while; the page is not stuck.";
				return vc.unlock(envelope, typed);
			})
			.then(function (result) {
				progress.textContent = "";
				// Signed out, or locked, while the key was derived: nothing of it is kept or shown.
				if (stale()) { wipeUnlockResult(result); return; }
				if (document.visibilityState === "hidden") {
					wipeUnlockResult(result);
					ui.notice(notice, "warn", "The vault opened while this tab was hidden, so it was locked again. Enter the master password once more.");
					return;
				}
				var vault;
				try { vault = vc.parseVault(result.plaintext); }
				catch (e) { result.vaultKey.fill(0); throw e; }
				finally { result.plaintext.fill(0); }
				server = { revision: download.revision, fingerprint: download.fingerprint, sizeBytes: download.sizeBytes, updatedAt: download.updatedAt };
				opened = {
					items: vault.items.slice(),
					vaultKey: result.vaultKey,
					envelope: parsedEnvelope,
					revision: download.revision,
					dirty: false,
					changes: 0
				};
				setStatus(describeServer(server));
				unlockForm.hidden = true;
				itemsSection.hidden = false;
				setDirty(false);
				renderItems();
				lastActivity = Date.now();
				armIdle();
				searchEl.focus();
				ui.notice(notice, "ok", result.usedCanonical
					? "Vault opened. Changes are uploaded only when you press Save to server."
					: "Vault opened with the password as it was typed when the vault was created. Changes are uploaded only when you press Save to server.");
			})
			.catch(function (err) {
				progress.textContent = "";
				if (stale()) { return; }
				showLocked();
				if (err === REMOVED) { return vaultRemoved(); }
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; }
				if (err && err.kind === vc.KINDS.AUTH) { ui.markField(passwordEl, true, notice); }
				ui.notice(notice, "err", describeVaultError(err));
			})
			.finally(function () {
				// The password has done its job; it does not stay in the field or in this closure.
				passwordEl.value = "";
				typed = null;
				busy = false;
				ui.setBusy(unlockForm, false);
				if (opened) { passwordEl.blur(); }
			});
	});

	// ---- download the encrypted backup (works locked: the bytes are what the server stores) ----
	function localDate(d) {
		function two(n) { return (n < 10 ? "0" : "") + n; }
		return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate());
	}
	function saveBytes(bytes, name) {
		var url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
		var a = ui.el("a", { href: url, download: name, hidden: "hidden" });
		document.body.appendChild(a);
		a.click();
		a.remove();
		setTimeout(function () { URL.revokeObjectURL(url); }, 60 * 1000);
	}
	backupButton.addEventListener("click", function () {
		if (backupBusy || !server) { return; }
		var g = generation();
		backupBusy = true;
		backupButton.disabled = true;
		ui.notice(notice, "ok", "Downloading the encrypted vault…");
		api.syncEnvelope()
			.then(function (d) {
				if (g !== generation()) { return; }
				if (!d) { return vaultRemoved(); }
				return vc.sha256Hex(d.envelope).then(function (hex) {
					if (g !== generation()) { return; }
					if (hex !== d.fingerprint || d.envelope.length !== d.sizeBytes) { throw new api.ApiError(api.KINDS.UNEXPECTED, 200); }
					saveBytes(d.envelope, "BitosX-backup-" + localDate(new Date()) + ".bitosx-backup");
					ui.notice(notice, "ok", "Saved the encrypted vault exactly as the server stores it (revision " + d.revision + ", " + formatSize(d.sizeBytes) +
						"). It opens only with the vault's master password; the desktop app restores it under Settings, Backup & Restore.");
				});
			})
			.catch(function (err) {
				if (g !== generation() || (err && err.kind === api.KINDS.UNAUTHENTICATED)) { return; }
				ui.notice(notice, "err", "The backup could not be downloaded: " + ui.describeError(err, "vault"));
			})
			.finally(function () { backupBusy = false; backupButton.disabled = false; });
	});

	// ---- rendering (textContent only; secrets are never in the DOM until revealed) ----
	function byName(a, b) { return a.name.localeCompare(b.name, undefined, { sensitivity: "base" }); }
	function byFavoriteThenName(a, b) {
		if (a.favorite !== b.favorite) { return a.favorite ? -1 : 1; }
		return byName(a, b);
	}
	function byRecentlyUpdated(a, b) { return (b.updatedAt - a.updatedAt) || byName(a, b); }

	function matches(item, needle) {
		if (!needle) { return true; }
		var n = needle.toLowerCase();
		return item.name.toLowerCase().indexOf(n) >= 0
			|| (item.username || "").toLowerCase().indexOf(n) >= 0
			|| item.urls.some(function (u) { return u.toLowerCase().indexOf(n) >= 0; });
	}

	function safeHttpUrl(text) {
		var u;
		try { u = new URL(text); } catch (e) { return null; }
		return (u.protocol === "https:" || u.protocol === "http:") ? u.href : null;
	}

	function renderItems() {
		ui.clear(itemsList);
		if (!opened) { return; }
		var needle = searchEl.value.trim();
		var favoritesOnly = favoritesEl.checked;
		var shown = opened.items
			.filter(function (it) { return (!favoritesOnly || it.favorite) && matches(it, needle); })
			.sort(sortEl.value === "updated" ? byRecentlyUpdated : byFavoriteThenName);
		countEl.textContent = shown.length === opened.items.length
			? opened.items.length + " item" + (opened.items.length === 1 ? "" : "s")
			: shown.length + " of " + opened.items.length + " items";
		if (shown.length === 0) {
			itemsList.appendChild(ui.el("li", { class: "vault-empty" },
				opened.items.length === 0 ? "This vault has no items yet." : favoritesOnly && !needle ? "No favorites yet." : "No items match."));
			return;
		}
		shown.forEach(function (item) {
			var li = ui.el("li", { class: "vault-item", "data-item-id": item.id });
			var head = ui.el("div", { class: "vault-item__head" });
			var title = ui.el("h3", { class: "vault-item__name" }, item.name || "(unnamed)");
			if (item.favorite) { title.appendChild(ui.el("span", { class: "vault-item__star", "aria-label": "Favorite", title: "Favorite" }, " ★")); }
			head.appendChild(title);
			head.appendChild(ui.el("span", { class: "vault-item__meta" }, "Updated " + ui.formatDate(item.updatedAt)));
			li.appendChild(head);

			var rows = ui.el("dl", { class: "vault-item__rows" });
			if (item.username) {
				rows.appendChild(ui.el("dt", null, "Username"));
				var ddU = ui.el("dd", null);
				ddU.appendChild(ui.el("span", { class: "vault-value" }, item.username));
				ddU.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-copy": "username" }, "Copy"));
				rows.appendChild(ddU);
			}
			if (item.password) {
				rows.appendChild(ui.el("dt", null, "Password"));
				var ddP = ui.el("dd", null);
				ddP.appendChild(ui.el("span", { class: "vault-value vault-secret", "data-secret": "hidden" }, "••••••••••••"));
				ddP.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-reveal": "password", "aria-pressed": "false" }, "Show"));
				ddP.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-copy": "password" }, "Copy"));
				rows.appendChild(ddP);
			}
			if (item.urls.length > 0) {
				rows.appendChild(ui.el("dt", null, item.urls.length === 1 ? "URL" : "URLs"));
				var ddL = ui.el("dd", null);
				item.urls.forEach(function (text) {
					var href = safeHttpUrl(text);
					var node = href
						? ui.el("a", { href: href, target: "_blank", rel: "noopener noreferrer", class: "vault-url" }, text)
						: ui.el("span", { class: "vault-url" }, text);
					ddL.appendChild(node);
				});
				rows.appendChild(ddL);
			}
			if (item.notes) {
				rows.appendChild(ui.el("dt", null, "Notes"));
				rows.appendChild(ui.el("dd", { class: "vault-notes" }, item.notes));
			}
			li.appendChild(rows);
			li.appendChild(itemActions(item, false));
			itemsList.appendChild(li);
		});
	}

	function itemActions(item, armed) {
		var actions = ui.el("div", { class: "vault-item__actions" });
		actions.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-edit": "1" }, "Edit"));
		if (armed) {
			// Asked for, then confirmed — or cancelled, as on the desktop.
			actions.appendChild(ui.el("button", { type: "button", class: "btn danger small", "data-delete": "1", "data-armed": "1" }, "Confirm delete"));
			actions.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-disarm": "1" }, "Keep it"));
		} else {
			actions.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-delete": "1" }, "Delete"));
		}
		return actions;
	}

	searchEl.addEventListener("input", renderItems);
	favoritesEl.addEventListener("change", renderItems);
	sortEl.addEventListener("change", renderItems);

	function findItem(node) {
		var li = node.closest("li[data-item-id]");
		if (!li || !opened) { return null; }
		var id = li.getAttribute("data-item-id");
		for (var i = 0; i < opened.items.length; i++) { if (opened.items[i].id === id) { return opened.items[i]; } }
		return null;
	}

	function copySecret(value) {
		ui.copySecret(value, function (level, text) { ui.notice(notice, level, text); });
	}

	itemsList.addEventListener("click", function (ev) {
		var btn = ev.target.closest("button[data-copy], button[data-reveal], button[data-edit], button[data-delete], button[data-disarm]");
		if (!btn) { return; }
		var item = findItem(btn);
		if (!item) { return; }
		var li = btn.closest("li[data-item-id]");
		if (btn.hasAttribute("data-edit")) { openEditor(item); return; }
		if (btn.hasAttribute("data-disarm")) {
			li.replaceChild(itemActions(item, false), btn.parentNode);
			li.querySelector("button[data-delete]").focus();
			return;
		}
		if (btn.hasAttribute("data-delete")) {
			if (btn.getAttribute("data-armed") !== "1") {
				li.replaceChild(itemActions(item, true), btn.parentNode);
				li.querySelector("button[data-disarm]").focus();
				return;
			}
			removeItem(item.id);
			return;
		}
		if (btn.hasAttribute("data-copy")) {
			var value = btn.getAttribute("data-copy") === "password" ? item.password : item.username;
			if (value) { copySecret(value); }
			return;
		}
		var span = btn.parentNode.querySelector(".vault-secret");
		var hidden = span.getAttribute("data-secret") === "hidden";
		span.textContent = hidden ? item.password : "••••••••••••";
		span.setAttribute("data-secret", hidden ? "shown" : "hidden");
		btn.textContent = hidden ? "Hide" : "Show";
		btn.setAttribute("aria-pressed", hidden ? "true" : "false");
	});

	// Lock is immediate, unsaved changes or not (the page says that locking discards them).
	$("vault-lock").addEventListener("click", function () { lock("Vault locked."); });

	// ---- the password generator's options: remembered per browser (they are not secret) ----
	var GENERATOR_KEY = "bitosx.generator";
	var genFields = { length: $("gen-length"), lowercase: $("gen-lowercase"), uppercase: $("gen-uppercase"), digits: $("gen-digits"), symbols: $("gen-symbols"), excludeAmbiguous: $("gen-ambiguous") };
	function readGeneratorFields() {
		return vc.generatorOptions({
			length: Number(genFields.length.value),
			lowercase: genFields.lowercase.checked, uppercase: genFields.uppercase.checked,
			digits: genFields.digits.checked, symbols: genFields.symbols.checked, excludeAmbiguous: genFields.excludeAmbiguous.checked
		});
	}
	function showGeneratorOptions(o) {
		genFields.length.value = String(o.length);
		["lowercase", "uppercase", "digits", "symbols", "excludeAmbiguous"].forEach(function (k) { genFields[k].checked = !!o[k]; });
	}
	function loadGeneratorOptions() {
		var o = vc.generatorOptions(null);
		try {
			var saved = JSON.parse(window.localStorage.getItem(GENERATOR_KEY) || "null");
			if (saved && typeof saved === "object") {
				var candidate = vc.generatorOptions({
					length: saved.length, lowercase: saved.lowercase === true, uppercase: saved.uppercase === true,
					digits: saved.digits === true, symbols: saved.symbols === true, excludeAmbiguous: saved.excludeAmbiguous === true
				});
				vc.validateGeneratorOptions(candidate);
				o = candidate;
			}
		} catch (e) { /* storage blocked or the value is not ours: defaults */ }
		showGeneratorOptions(o);
	}
	function saveGeneratorOptions(o) {
		try { window.localStorage.setItem(GENERATOR_KEY, JSON.stringify(o)); } catch (e) { /* not remembered, still used */ }
	}
	genFields.length.setAttribute("min", String(vc.GENERATOR_MIN_LENGTH));
	genFields.length.setAttribute("max", String(vc.GENERATOR_MAX_LENGTH));
	loadGeneratorOptions();
	Object.keys(genFields).forEach(function (k) {
		genFields[k].addEventListener("change", function () {
			var o = readGeneratorFields();
			try { vc.validateGeneratorOptions(o); }
			catch (e) { ui.markField(genFields.length, k === "length", editorNotice); ui.notice(editorNotice, "err", e.message); return; }
			ui.markField(genFields.length, false);
			ui.notice(editorNotice, "ok", "");
			saveGeneratorOptions(o);
		});
	});

	// ---- editing (in memory, until Save to server) ----
	var FIELD_IDS = ["edit-name", "edit-username", "edit-password", "edit-urls", "edit-notes"];
	function editorFields() {
		return { name: $("edit-name").value, username: $("edit-username").value, password: $("edit-password").value,
			urls: $("edit-urls").value, notes: $("edit-notes").value, favorite: $("edit-favorite").checked };
	}
	function editorModified() {
		if (editing === null || !editorSnapshot) { return false; }
		var now = editorFields();
		return Object.keys(now).some(function (k) { return now[k] !== editorSnapshot[k]; });
	}

	function splitUrls(text) {
		// One per line, as the label says (and as the desktop editor does from phase 8 on).
		return text.split(/\r\n|\r|\n/).map(function (u) { return u.trim(); }).filter(function (u) { return u.length > 0; });
	}

	// The checks the desktop makes (VaultValidation), field by field, so a problem is shown at the
	// field while typing, not only after Save item.
	function fieldProblem(id) {
		var v = $(id).value;
		var L = vc.LIMITS;
		function whole(text, what) { return vc.isWellFormed(text) ? null : what + " contains an incomplete character (half of an emoji or symbol)."; }
		switch (id) {
			case "edit-name":
				if (v.trim().length === 0) { return "Name is required."; }
				if (v.trim().length > L.name) { return "Name must be at most " + L.name + " characters."; }
				return whole(v, "The name");
			case "edit-username":
				if (v.trim().length > L.username) { return "Username must be at most " + L.username + " characters."; }
				return whole(v, "The username");
			case "edit-password":
				if (v.length > L.password) { return "Password must be at most " + L.password + " characters."; }
				return whole(v, "The password");
			case "edit-notes":
				if (v.length > L.notes) { return "Notes must be at most " + L.notes + " characters."; }
				return whole(v, "The notes");
			case "edit-urls":
				var urls = splitUrls(v);
				if (urls.length > L.urls) { return "An item may have at most " + L.urls + " URLs."; }
				for (var i = 0; i < urls.length; i++) {
					if (urls[i].length > L.url) { return "A URL must be at most " + L.url + " characters."; }
					if (!vc.isWellFormed(urls[i])) { return "A URL contains an incomplete character."; }
					if (!safeHttpUrl(urls[i])) { return "'" + urls[i] + "' is not a valid absolute http(s) URL."; }
				}
				return null;
		}
		return null;
	}
	function showFieldProblem(id, problem) {
		var box = $(id + "-error");
		box.textContent = problem || "";
		box.hidden = !problem;
		$(id).setAttribute("aria-invalid", problem ? "true" : "false");
		var described = [id + "-error"];
		if (id === "edit-notes") { described.push("edit-notes-count"); }
		if (id === "edit-password") { described.push("edit-password-strength"); }
		if (problem) { $(id).setAttribute("aria-describedby", described.join(" ")); }
		else if (described.length > 1) { $(id).setAttribute("aria-describedby", described.slice(1).join(" ")); }
		else { $(id).removeAttribute("aria-describedby"); }
	}
	function updateNotesCount() {
		$("edit-notes-count").textContent = $("edit-notes").value.length + " / " + vc.LIMITS.notes + " characters";
	}
	function updateStrength() {
		var pw = $("edit-password").value;
		$("edit-password-strength").textContent = pw ? "Strength: " + vc.STRENGTH_NAMES[vc.estimateStrength(pw)] +
			" (an estimate from length and patterns; it cannot tell common words or leaked passwords)" : "";
	}
	FIELD_IDS.forEach(function (id) {
		$(id).addEventListener("input", function () {
			showFieldProblem(id, fieldProblem(id));
			if (id === "edit-notes") { updateNotesCount(); }
			if (id === "edit-password") { updateStrength(); }
		});
	});

	function openEditor(item) {
		if (!opened) { return; }
		if (editorModified() && !window.confirm("Discard what you typed in the editor?")) { return; }
		editing = item ? item.id : "";
		$("vault-editor-title").textContent = item ? "Edit login" : "New login";
		$("edit-name").value = item ? item.name : "";
		$("edit-username").value = item && item.username ? item.username : "";
		$("edit-password").value = item && item.password ? item.password : "";
		$("edit-password").type = "password";
		$("edit-password-toggle").textContent = "Show";
		$("edit-password-toggle").setAttribute("aria-pressed", "false");
		$("edit-urls").value = item ? item.urls.join("\n") : "";
		$("edit-notes").value = item && item.notes ? item.notes : "";
		$("edit-favorite").checked = !!(item && item.favorite);
		FIELD_IDS.forEach(function (id) { showFieldProblem(id, null); });
		updateNotesCount();
		updateStrength();
		ui.notice(editorNotice, "ok", "");
		editorSnapshot = editorFields();
		editor.hidden = false;
		$("edit-name").focus();
	}

	function closeEditor() {
		editing = null;
		editorSnapshot = null;
		editor.hidden = true;
		// Nothing typed stays in the fields once the editor is closed.
		FIELD_IDS.forEach(function (id) { $(id).value = ""; showFieldProblem(id, null); });
		$("edit-password").type = "password";
		$("edit-favorite").checked = false;
		$("edit-password-strength").textContent = "";
		$("edit-notes-count").textContent = "";
		ui.notice(editorNotice, "ok", "");
	}

	$("vault-add").addEventListener("click", function () { openEditor(null); });
	$("edit-cancel").addEventListener("click", function () { closeEditor(); });
	$("edit-password-toggle").addEventListener("click", function () {
		var box = $("edit-password");
		var show = box.type === "password";
		box.type = show ? "text" : "password";
		this.textContent = show ? "Hide" : "Show";
		this.setAttribute("aria-pressed", show ? "true" : "false");
	});
	$("edit-password-generate").addEventListener("click", function () {
		var o = readGeneratorFields();
		var pw;
		try { pw = vc.generatePassword(o); }
		catch (e) { ui.notice(editorNotice, "err", e instanceof vc.VaultError ? e.message : "No password could be generated."); return; }
		saveGeneratorOptions(o);
		var box = $("edit-password");
		box.value = pw;
		// As on the desktop, a generated password is shown, so it can be checked before saving.
		box.type = "text";
		$("edit-password-toggle").textContent = "Hide";
		$("edit-password-toggle").setAttribute("aria-pressed", "true");
		showFieldProblem("edit-password", null);
		updateStrength();
		ui.notice(editorNotice, "ok", "");
	});

	editor.addEventListener("submit", function (ev) {
		ev.preventDefault();
		if (!opened || editing === null) { return; }
		var firstBad = null;
		FIELD_IDS.forEach(function (id) {
			var problem = fieldProblem(id);
			showFieldProblem(id, problem);
			if (problem && !firstBad) { firstBad = { id: id, problem: problem }; }
		});
		if (firstBad) {
			ui.notice(editorNotice, "err", firstBad.problem);
			$(firstBad.id).focus();
			return;
		}
		var index = editing === "" ? -1 : opened.items.findIndex(function (i) { return i.id === editing; });
		var existing = index >= 0 ? opened.items[index] : null;
		if (!existing && opened.items.length >= vc.MAX_ITEMS) {
			ui.notice(editorNotice, "err", "This vault already holds " + vc.MAX_ITEMS + " items, the most the web vault can save.");
			return;
		}
		var now = new Date();
		var created = existing ? existing.createdAt : now;
		var notes = $("edit-notes").value;
		var item = Object.freeze({
			id: existing ? existing.id : vc.newId(),
			type: "login",
			name: $("edit-name").value.trim(),
			username: $("edit-username").value.trim() || null,
			password: $("edit-password").value || null,
			urls: Object.freeze(splitUrls($("edit-urls").value)),
			notes: notes.trim().length > 0 ? notes : null,   // as the desktop editor: whitespace only is no notes
			favorite: $("edit-favorite").checked,
			createdAt: created,
			createdAtText: existing ? existing.createdAtText : null,
			updatedAt: now < created ? created : now   // Vault.Update: never earlier than CreatedAt
		});
		try { vc.validateItem(item); }
		catch (err) {
			ui.notice(editorNotice, "err", err instanceof vc.VaultError ? err.message : "The item could not be saved.");
			return;
		}
		// Changed in place, new at the end: the stored order is the desktop's, not the display's.
		var items = opened.items.slice();
		if (index >= 0) { items[index] = item; } else { items.push(item); }
		opened.items = items;
		closeEditor();
		markChanged();
		renderItems();
		ui.notice(notice, "ok", (existing ? "Item updated" : "Item added") + " in this browser. Press Save to server to upload the encrypted vault.");
	});

	function removeItem(id) {
		if (!opened) { return; }
		opened.items = opened.items.filter(function (i) { return i.id !== id; });
		if (editing === id) { closeEditor(); }
		markChanged();
		renderItems();
		ui.notice(notice, "ok", "Item deleted in this browser. Press Save to server to upload the encrypted vault.");
	}

	// ---- saving: encrypt here, upload with compare-and-set ----
	function describeSaveError(err, sent) {
		if (err instanceof api.ApiError) {
			if (sent && (err.kind === api.KINDS.NETWORK || err.kind === api.KINDS.TIMEOUT || err.kind === api.KINDS.UNEXPECTED)) {
				return "The upload got no answer: " + ui.describeError(err, "vault") + " The server may or may not have stored it; your changes are still here. " +
					"Press Save to server again: if the earlier upload did arrive, this page recognises it.";
			}
			return ui.describeError(err, "vault") + " Nothing was uploaded.";
		}
		if (err instanceof vc.VaultError) { return err.message + " Nothing was uploaded."; }
		return "The vault could not be saved. Nothing was uploaded.";
	}

	// Every item is checked before anything is encrypted, and a failure names the item.
	function checkItems(items) {
		if (items.length > vc.MAX_ITEMS) { throw new vc.VaultError(vc.KINDS.CONTENT, "The vault holds more than " + vc.MAX_ITEMS + " items, the most the web vault can save."); }
		items.forEach(function (item) {
			try { vc.validateItem(item); }
			catch (e) {
				if (e instanceof vc.VaultError) { throw new vc.VaultError(vc.KINDS.CONTENT, "The item '" + (item.name || "(unnamed)") + "' cannot be saved: " + e.message); }
				throw e;
			}
		});
	}

	// Encrypts the given vault's items and uploads them against baseRevision. Resolves to
	// { stored, next }; rejects with ApiError CONFLICT when the server moved on. Never throws
	// synchronously, and the plaintext is wiped on every path.
	function uploadAsync(o, baseRevision, attempt) {
		return Promise.resolve().then(function () {
			checkItems(o.items);
			var plaintext = vc.serializeVault({ items: o.items });
			return vc.encryptContent(o.envelope, o.vaultKey, plaintext).finally(function () { plaintext.fill(0); });
		}).then(function (next) {
			var bytes = vc.serializeEnvelope(next);
			return vc.sha256Hex(bytes).then(function (fingerprint) {
				attempt.sent = true;
				attempt.fingerprint = fingerprint;
				attempt.next = next;
				return api.syncUpload(baseRevision, bytes).then(function (stored) {
					// What the server says it stored must be what was sent.
					if (stored.fingerprint !== fingerprint || stored.sizeBytes !== bytes.length) { throw new api.ApiError(api.KINDS.UNEXPECTED, 200); }
					return { stored: stored, next: next };
				});
			});
		});
	}

	// The upload is stored: adopt it, and say whether edits made meanwhile are still to be saved.
	function adoptStored(o, stored, next, changesUploaded, successSentence) {
		server = stored;
		uncertainUpload = null;
		setStatus(describeServer(stored));
		if (opened !== o) {
			ui.notice(notice, "ok", "Saved: the server now holds revision " + stored.revision + ". The vault was locked meanwhile.");
			return;
		}
		o.envelope = next;
		o.revision = stored.revision;
		if (o.changes !== changesUploaded) {
			setDirty(true);
			ui.notice(notice, "warn", "Saved revision " + stored.revision + ", but the changes you made during the upload are not on the server yet. Press Save to server again.");
			return;
		}
		setDirty(false);
		ui.notice(notice, "ok", successSentence || ("Saved: the server now holds revision " + stored.revision + ". Sync in the desktop app to get it there."));
	}

	function showConflict() {
		conflictPanel.hidden = false;
		overwriteRow.hidden = false;
		conflictText.textContent = "Another device changed the vault on the server after you opened it here. Nothing was uploaded. Choose: reload the server's vault " +
			"(your changes here are discarded), or replace the server's vault with this browser's version (the other device's changes are lost there).";
		ui.notice(notice, "err", "Another device changed the vault on the server first. Nothing was uploaded; choose below.");
	}

	// A 409: perhaps the earlier upload whose answer never came did arrive. Then it is ours.
	function handleConflict(o) {
		var pending = uncertainUpload;
		if (!pending || pending.opened !== o) { showConflict(); return Promise.resolve(); }
		return api.syncStatus().then(function (status) {
			if (opened !== o) { return; }
			if (status && status.fingerprint === pending.fingerprint) {
				adoptStored(o, status, pending.next, pending.changes, "Saved: the earlier upload had reached the server, which holds revision " + status.revision + ".");
				return;
			}
			uncertainUpload = null;
			showConflict();
		}, function () { showConflict(); });
	}

	function saveAsync(baseRevision, successSentence) {
		if (busy || !opened) { return Promise.resolve(); }
		var o = opened;
		var g = generation();
		var changesAtStart = o.changes;
		var attempt = { sent: false };
		busy = true;
		saveButton.disabled = true;
		overwriteButton.disabled = true;
		ui.notice(notice, "ok", "");
		progress.textContent = "";
		hideConflict();
		return uploadAsync(o, baseRevision, attempt)
			.then(function (r) {
				if (g !== generation()) { return; } // signed out meanwhile: nothing here to update
				adoptStored(o, r.stored, r.next, changesAtStart, typeof successSentence === "function" ? successSentence(r.stored) : successSentence);
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				if (err instanceof api.ApiError && err.kind === api.KINDS.CONFLICT) { return handleConflict(o); }
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) {
					// The account page signs out (and so locks this vault) when a session ends; be sure.
					if (opened) { lock("Your session has ended, so the vault was locked. Unsaved changes were discarded."); }
					return;
				}
				if (attempt.sent && err instanceof api.ApiError && (err.kind === api.KINDS.NETWORK || err.kind === api.KINDS.TIMEOUT || err.kind === api.KINDS.UNEXPECTED)) {
					uncertainUpload = { opened: o, fingerprint: attempt.fingerprint, next: attempt.next, changes: changesAtStart };
				}
				if (opened === o || opened === null) { ui.notice(notice, "err", describeSaveError(err, attempt.sent)); }
			})
			.finally(function () {
				busy = false;
				if (opened) { saveButton.disabled = !opened.dirty; overwriteButton.disabled = !overwriteAck.checked; }
			});
	}

	saveButton.addEventListener("click", function () {
		if (!opened || !opened.dirty) { return; }
		saveAsync(opened.revision);
	});

	overwriteAck.addEventListener("change", function () { overwriteButton.disabled = !overwriteAck.checked || busy; });

	// The conflict's way out in this browser's favour. It is refused when the server's vault key is
	// protected differently from the one opened here (the master password was changed, or the key
	// rotated, on another device): re-encrypting under the old header would quietly bring the old
	// master password back. Still compare-and-set against what the server holds right now, so a
	// device that uploads in between is not silently overwritten.
	var KEY_WRAP_CHANGED = { keyWrapChanged: true };
	overwriteButton.addEventListener("click", function () {
		if (busy || !opened || !overwriteAck.checked) { return; }
		var o = opened;
		var g = generation();
		busy = true;
		overwriteButton.disabled = true;
		saveButton.disabled = true;
		progress.textContent = "Checking the vault on the server…";
		api.syncEnvelope()
			.then(function (d) {
				if (!d) { return 0; } // nothing stored any more: compare-and-set against "nothing"
				return vc.sha256Hex(d.envelope).then(function (hex) {
					if (hex !== d.fingerprint || d.envelope.length !== d.sizeBytes) { throw new api.ApiError(api.KINDS.UNEXPECTED, 200); }
					var serverEnvelope;
					try { serverEnvelope = vc.parseEnvelope(d.envelope); } catch (e) { throw KEY_WRAP_CHANGED; }
					if (!vc.sameKeyWrap(serverEnvelope, o.envelope)) { throw KEY_WRAP_CHANGED; }
					return d.revision;
				});
			})
			.then(function (revision) {
				progress.textContent = "";
				busy = false;
				if (g !== generation() || opened !== o) { return; }
				return saveAsync(revision, function (stored) {
					return "Saved: the server now holds this browser's version (revision " + stored.revision + "). Other devices offer to download it when they sync; " +
						"a device with unsynced changes of its own asks which version to keep.";
				});
			})
			.catch(function (err) {
				progress.textContent = "";
				busy = false;
				if (g !== generation() || opened !== o) { return; }
				if (err === KEY_WRAP_CHANGED) {
					overwriteRow.hidden = true;
					overwriteAck.checked = false;
					conflictText.textContent = "The vault on the server is protected differently now: its master password or encryption settings were changed on another device. " +
						"Replacing it from this browser would undo that change, so it is not offered. Reload the server's vault (your changes here are discarded) and make them again.";
					ui.notice(notice, "err", "The server's vault has a new master password or key. Reload it to continue; nothing was uploaded.");
					return;
				}
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; }
				ui.notice(notice, "err", describeSaveError(err, false));
			})
			.finally(function () {
				if (!busy && opened) { saveButton.disabled = !opened.dirty; overwriteButton.disabled = !overwriteAck.checked; }
			});
	});

	// The other way out: drop the changes here and open the server's vault again (master password needed).
	$("vault-reload").addEventListener("click", function () {
		if (busy) { return; }
		lock();
		loadStatus().then(function () {
			if (server) { ui.notice(notice, "ok", "Changes discarded. Enter the master password to open the server's vault again."); }
		});
	});

	// ---- following the account ----
	document.addEventListener("bitosx:signed-in", function () { loadStatus(); });
	document.addEventListener("bitosx:signed-out", function () { hidePanel(); });

	window.bitosxVault = Object.freeze({
		isUnlocked: function () { return opened !== null; },
		hasUnsavedChanges: hasUnsavedChanges,
		lock: function () { lock("Vault locked."); }
	});
})();
