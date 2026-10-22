// The vault panel (vault.bitosx.se, phase 4): read the vault in the browser.
//
// The server holds the vault as the encrypted file the desktop app uploaded and cannot open it.
// This page downloads those bytes, checks them against what the server states about them, and
// opens them here with the master password — Argon2id and AES-256-GCM exactly as the desktop does
// it (vault-crypto.js). The master password and the decrypted items exist only in this script's
// memory, only while unlocked; nothing is written anywhere, and nothing decrypted is ever sent.
// Since phase 5 the vault can be edited here: changes are encrypted in the browser under the same
// vault key (fresh nonce, VaultCryptor.ReEncryptContent) and uploaded only on "Save to server",
// with the same compare-and-set rule the desktop uses — if another device changed the vault on the
// server first, nothing is overwritten and the user chooses.
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
	var countEl = $("vault-count");

	var server = null;      // what the server holds (public metadata), or null
	// While unlocked: { items, vaultKey, envelope, revision, dirty } — the only copy of the decrypted
	// vault and of the vault key. Both exist only here, only until lock.
	var opened = null;
	var idleTimer = null;
	var clipboardTimer = null;
	var busy = false;
	var editing = null;     // the id of the item in the editor, or "" for a new one, or null when closed

	var editor = $("vault-editor");
	var editorNotice = $("vault-editor-notice");
	var dirtyNote = $("vault-dirty");
	var saveButton = $("vault-save");
	var conflictPanel = $("vault-conflict");
	var overwriteAck = $("vault-overwrite-ack");
	var overwriteButton = $("vault-overwrite");

	// ---- showing state ----
	function setStatus(text) { statusText.textContent = text; }

	function showLocked() {
		if (opened && opened.vaultKey) { opened.vaultKey.fill(0); }
		opened = null;
		clearIdle();
		closeEditor();
		hideConflict();
		ui.clear(itemsList);
		countEl.textContent = "";
		searchEl.value = "";
		itemsSection.hidden = true;
		unlockForm.hidden = server === null;
		passwordEl.value = "";
		progress.textContent = "";
		setDirty(false);
	}

	function setDirty(value) {
		if (opened) { opened.dirty = value; }
		dirtyNote.hidden = !value;
		saveButton.disabled = !value || busy;
	}

	function hideConflict() {
		conflictPanel.hidden = true;
		overwriteAck.checked = false;
		overwriteButton.disabled = true;
	}

	function lock(message) {
		var had = opened !== null;
		showLocked();
		if (had) { ui.notice(notice, "ok", message || "Vault locked."); }
	}

	function hidePanel() {
		lock();
		server = null;
		panel.hidden = true;
		ui.notice(notice, "ok", "");
	}

	// ---- idle lock (separate from, and shorter than, the account sign-out) ----
	function clearIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } }
	function armIdle() {
		clearIdle();
		idleTimer = setTimeout(function () {
			lock("Vault locked after " + Math.round(cfg.vaultIdleTimeoutMs / 60000) + " minutes without activity.");
		}, cfg.vaultIdleTimeoutMs);
	}
	["pointerdown", "keydown", "scroll", "touchstart"].forEach(function (evt) {
		document.addEventListener(evt, function () { if (opened) { armIdle(); } }, { passive: true });
	});
	window.addEventListener("pagehide", function () { lock(); });
	window.addEventListener("beforeunload", function (ev) {
		// Unsaved changes exist only in this page; leaving discards them. The browser shows its own prompt.
		if (opened && opened.dirty) { ev.preventDefault(); ev.returnValue = ""; }
	});
	document.addEventListener("visibilitychange", function () {
		// A hidden tab is an unattended screen: lock, as the desktop does on workstation lock —
		// unless there are unsaved changes, which a lock would discard; the idle lock still applies.
		if (document.visibilityState === "hidden" && opened && !opened.dirty) { lock("Vault locked when the tab was hidden."); }
	});

	// ---- what the server holds ----
	function formatSize(bytes) {
		if (bytes < 1024) { return bytes + " bytes"; }
		if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(1) + " KiB"; }
		return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
	}

	function loadStatus() {
		panel.hidden = false;
		ui.notice(notice, "ok", "");
		setStatus("Checking what the server holds…");
		return api.syncStatus()
			.then(function (status) {
				server = status;
				if (!status) {
					setStatus("The server holds no vault for this account yet. Sync from the desktop app (Account → Sync now) and it appears here.");
				} else {
					setStatus("Encrypted vault on the server: revision " + status.revision + ", " + formatSize(status.sizeBytes)
						+ ", stored " + ui.formatDate(status.updatedAt) + ". Enter the vault's master password to read it in this browser.");
				}
				showLocked();
			})
			.catch(function (err) {
				server = null;
				showLocked();
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; } // account.js handles the sign-out
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

	unlockForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		if (busy || !server) { return; }
		var typed = passwordEl.value;
		if (typed.length === 0) {
			ui.notice(notice, "err", "Enter the master password of your vault.");
			return;
		}
		busy = true;
		var parsedEnvelope = null;
		ui.notice(notice, "ok", "");
		ui.setBusy(unlockForm, true);
		progress.textContent = "Downloading the encrypted vault…";

		api.syncEnvelope()
			.then(function (download) {
				if (!download) { throw new vc.VaultError(vc.KINDS.FORMAT, "nothing stored"); }
				// The server's own statements about the bytes must hold for the bytes it sent.
				return vc.sha256Hex(download.envelope).then(function (hex) {
					if (hex !== download.fingerprint || download.envelope.length !== download.sizeBytes) {
						throw new api.ApiError(api.KINDS.UNEXPECTED, 200);
					}
					server = { revision: download.revision, fingerprint: download.fingerprint, sizeBytes: download.sizeBytes, updatedAt: download.updatedAt };
					return vc.parseEnvelope(download.envelope);
				});
			})
			.then(function (envelope) {
				parsedEnvelope = envelope;
				var p = envelope.kdfParameters;
				progress.textContent = "Deriving the key: Argon2id with " + Math.round(p.memoryKiB / 1024) + " MiB, " + p.iterations
					+ " pass" + (p.iterations === 1 ? "" : "es") + ". In a browser this can take a while; the page is not stuck.";
				return vc.unlock(envelope, typed);
			})
			.then(function (result) {
				progress.textContent = "";
				var vault;
				try { vault = vc.parseVault(result.plaintext); }
				finally { result.plaintext.fill(0); }
				opened = {
					items: vault.items.slice().sort(byFavoriteThenName),
					vaultKey: result.vaultKey,
					envelope: parsedEnvelope,
					revision: server.revision,
					dirty: false
				};
				unlockForm.hidden = true;
				itemsSection.hidden = false;
				setDirty(false);
				renderItems("");
				armIdle();
				searchEl.focus();
				ui.notice(notice, "ok", result.usedCanonical
					? "Vault opened. Changes are uploaded only when you press Save to server."
					: "Vault opened with the password as it was typed when the vault was created. Changes are uploaded only when you press Save to server.");
			})
			.catch(function (err) {
				progress.textContent = "";
				showLocked();
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; }
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

	// ---- rendering (textContent only; secrets are never in the DOM until revealed) ----
	function byFavoriteThenName(a, b) {
		if (a.favorite !== b.favorite) { return a.favorite ? -1 : 1; }
		return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
	}

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

	function renderItems(needle) {
		ui.clear(itemsList);
		if (!opened) { return; }
		var shown = opened.items.filter(function (it) { return matches(it, needle); });
		countEl.textContent = shown.length === opened.items.length
			? opened.items.length + " item" + (opened.items.length === 1 ? "" : "s")
			: shown.length + " of " + opened.items.length + " items";
		if (shown.length === 0) {
			itemsList.appendChild(ui.el("li", { class: "vault-empty" }, opened.items.length === 0 ? "This vault has no items yet." : "No items match."));
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
			var actions = ui.el("div", { class: "vault-item__actions" });
			actions.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-edit": "1" }, "Edit"));
			actions.appendChild(ui.el("button", { type: "button", class: "btn ghost small", "data-delete": "1" }, "Delete"));
			li.appendChild(actions);
			itemsList.appendChild(li);
		});
	}

	searchEl.addEventListener("input", function () { renderItems(searchEl.value.trim()); });

	function findItem(node) {
		var li = node.closest("li[data-item-id]");
		if (!li || !opened) { return null; }
		var id = li.getAttribute("data-item-id");
		for (var i = 0; i < opened.items.length; i++) { if (opened.items[i].id === id) { return opened.items[i]; } }
		return null;
	}

	// Copy a secret, and clear the clipboard again after a while — only if it still holds what
	// we put there, so something the user copied afterwards is never erased. If the clipboard
	// cannot be read back (no permission), it is left alone.
	function copySecret(value) {
		if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
			ui.notice(notice, "err", "This browser does not allow copying from the page. Reveal the value instead.");
			return;
		}
		navigator.clipboard.writeText(value).then(function () {
			ui.notice(notice, "ok", "Copied. The clipboard is cleared again in " + Math.round(cfg.clipboardClearMs / 1000) + " seconds.");
			if (clipboardTimer) { clearTimeout(clipboardTimer); }
			clipboardTimer = setTimeout(function () {
				clipboardTimer = null;
				if (typeof navigator.clipboard.readText !== "function") { return; }
				navigator.clipboard.readText().then(function (current) {
					if (current === value) { return navigator.clipboard.writeText(""); }
				}).catch(function () { /* cannot read it back: leave it */ });
			}, cfg.clipboardClearMs);
		}).catch(function () {
			ui.notice(notice, "err", "Copying was not allowed by the browser. Reveal the value instead.");
		});
	}

	itemsList.addEventListener("click", function (ev) {
		var btn = ev.target.closest("button[data-copy], button[data-reveal], button[data-edit], button[data-delete]");
		if (!btn) { return; }
		var item = findItem(btn);
		if (!item) { return; }
		if (btn.hasAttribute("data-edit")) { openEditor(item); return; }
		if (btn.hasAttribute("data-delete")) {
			// Asked for, then confirmed: the first press arms the button, the second deletes.
			if (btn.getAttribute("data-armed") !== "1") {
				btn.setAttribute("data-armed", "1");
				btn.textContent = "Confirm delete";
				btn.classList.add("danger");
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

	$("vault-lock").addEventListener("click", function () { lock("Vault locked."); });

	// ---- editing (in memory, until Save to server) ----
	function openEditor(item) {
		if (!opened) { return; }
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
		ui.notice(editorNotice, "ok", "");
		editor.hidden = false;
		$("edit-name").focus();
	}

	function closeEditor() {
		editing = null;
		editor.hidden = true;
		// Nothing typed stays in the fields once the editor is closed.
		["edit-name", "edit-username", "edit-password", "edit-urls", "edit-notes"].forEach(function (id) { $(id).value = ""; });
		$("edit-favorite").checked = false;
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
		$("edit-password").value = vc.generatePassword(24);
	});

	editor.addEventListener("submit", function (ev) {
		ev.preventDefault();
		if (!opened || editing === null) { return; }
		var existing = editing === "" ? null : opened.items.find(function (i) { return i.id === editing; });
		var now = new Date();
		var created = existing ? existing.createdAt : now;
		var item = Object.freeze({
			id: existing ? existing.id : vc.newId(),
			type: "login",
			name: $("edit-name").value.trim(),
			username: $("edit-username").value.trim() || null,
			password: $("edit-password").value || null,
			urls: Object.freeze($("edit-urls").value.split(/\r?\n/).map(function (u) { return u.trim(); }).filter(function (u) { return u.length > 0; })),
			notes: $("edit-notes").value.length > 0 ? $("edit-notes").value : null,
			favorite: $("edit-favorite").checked,
			createdAt: created,
			updatedAt: now < created ? created : now   // Vault.Update: never earlier than CreatedAt
		});
		try { vc.validateItem(item); }
		catch (err) {
			ui.notice(editorNotice, "err", err instanceof vc.VaultError ? err.message : "The item could not be saved.");
			return;
		}
		var items = opened.items.filter(function (i) { return i.id !== item.id; });
		items.push(item);
		opened.items = items.sort(byFavoriteThenName);
		closeEditor();
		setDirty(true);
		renderItems(searchEl.value.trim());
		ui.notice(notice, "ok", (existing ? "Item updated" : "Item added") + " in this browser. Press Save to server to upload the encrypted vault.");
	});

	function removeItem(id) {
		if (!opened) { return; }
		opened.items = opened.items.filter(function (i) { return i.id !== id; });
		if (editing === id) { closeEditor(); }
		setDirty(true);
		renderItems(searchEl.value.trim());
		ui.notice(notice, "ok", "Item deleted in this browser. Press Save to server to upload the encrypted vault.");
	}

	// ---- saving: encrypt here, upload with compare-and-set ----
	function describeSaveError(err) {
		if (err instanceof api.ApiError) { return ui.describeError(err, "vault"); }
		if (err instanceof vc.VaultError) { return err.message + " Nothing was uploaded."; }
		return "The vault could not be saved. Nothing was uploaded.";
	}

	// Encrypts the current items and uploads them against baseRevision. Resolves to the server's
	// new status; rejects with ApiError CONFLICT when the server moved on.
	function uploadAsync(baseRevision) {
		var plaintext = vc.serializeVault({ items: opened.items });
		return vc.encryptContent(opened.envelope, opened.vaultKey, plaintext)
			.then(function (next) {
				plaintext.fill(0);
				var bytes = vc.serializeEnvelope(next);
				return vc.sha256Hex(bytes).then(function (fingerprint) {
					return api.syncUpload(baseRevision, bytes).then(function (stored) {
						// What the server says it stored must be what was sent.
						if (stored.fingerprint !== fingerprint || stored.sizeBytes !== bytes.length) { throw new api.ApiError(api.KINDS.UNEXPECTED, 200); }
						opened.envelope = next;
						opened.revision = stored.revision;
						server = stored;
						return stored;
					});
				});
			});
	}

	function saveAsync(baseRevision, successSentence) {
		if (busy || !opened) { return Promise.resolve(); }
		busy = true;
		saveButton.disabled = true;
		ui.notice(notice, "ok", "");
		progress.textContent = "";
		hideConflict();
		return uploadAsync(baseRevision)
			.then(function (stored) {
				setDirty(false);
				setStatus("Encrypted vault on the server: revision " + stored.revision + ", " + formatSize(stored.sizeBytes) + ", stored " + ui.formatDate(stored.updatedAt) + ".");
				ui.notice(notice, "ok", successSentence || ("Saved: the server now holds revision " + stored.revision + ". Sync in the desktop app to get it there."));
			})
			.catch(function (err) {
				if (err instanceof api.ApiError && err.kind === api.KINDS.CONFLICT) {
					conflictPanel.hidden = false;
					ui.notice(notice, "err", "Another device changed the vault on the server first. Nothing was uploaded; choose below.");
					return;
				}
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; } // account.js shows the sign-in
				ui.notice(notice, "err", describeSaveError(err));
			})
			.finally(function () {
				busy = false;
				if (opened) { saveButton.disabled = !opened.dirty; }
			});
	}

	saveButton.addEventListener("click", function () {
		if (!opened || !opened.dirty) { return; }
		saveAsync(opened.revision);
	});

	overwriteAck.addEventListener("change", function () { overwriteButton.disabled = !overwriteAck.checked || busy; });

	// The conflict's way out in this browser's favour: still compare-and-set against the revision
	// the server holds right now, so a device that uploads in between is not silently overwritten.
	overwriteButton.addEventListener("click", function () {
		if (!opened || !overwriteAck.checked) { return; }
		busy = true;
		api.syncStatus()
			.then(function (status) {
				busy = false;
				return saveAsync(status ? status.revision : 0, "Saved: the server now holds this browser's version. Every other device will be asked which vault to keep.");
			})
			.catch(function (err) {
				busy = false;
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { return; }
				ui.notice(notice, "err", describeSaveError(err));
			});
	});

	// The other way out: drop the changes here and open the server's vault again (master password needed).
	$("vault-reload").addEventListener("click", function () {
		lock("Changes discarded. Enter the master password to open the server's vault again.");
		loadStatus();
	});

	// ---- following the account ----
	document.addEventListener("bitosx:signed-in", function () { loadStatus(); });
	document.addEventListener("bitosx:signed-out", function () { hidePanel(); });

	window.bitosxVault = Object.freeze({
		isUnlocked: function () { return opened !== null; },
		hasUnsavedChanges: function () { return opened !== null && opened.dirty; },
		lock: function () { lock("Vault locked."); }
	});
})();
