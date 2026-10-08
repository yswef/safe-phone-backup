/* Phone Media Vault UI — works inside pywebview (window.pywebview.api) and in
 * browser mode (fetch /api/<method> with the per-run token). */
"use strict";

const $ = (id) => document.getElementById(id);
const state = { info: null, device: null, sources: [], job: null, pollTimer: null, onJobDone: null };

/* ---------------------------------------------------------------- bridge */
function bridgeReady() {
  return new Promise((resolve) => {
    if (window.PMV_TOKEN) return resolve();
    if (window.pywebview && window.pywebview.api) return resolve();
    window.addEventListener("pywebviewready", () => resolve(), { once: true });
  });
}

async function call(method, ...args) {
  let response;
  try {
    if (window.pywebview && window.pywebview.api && !window.PMV_TOKEN) {
      response = await window.pywebview.api[method](...args);
    } else {
      const r = await fetch("api/" + method, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-PMV-Token": window.PMV_TOKEN || "" },
        body: JSON.stringify({ args }),
      });
      response = await r.json();
    }
  } catch (err) {
    response = { ok: false, error: "تعذّر الاتصال بالتطبيق: " + err };
  }
  if (!response || !response.ok) {
    const error = new Error((response && response.error) || "خطأ غير معروف");
    error.details = response && response.details;
    throw error;
  }
  return response.data;
}

/* ---------------------------------------------------------------- helpers */
function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function humanSize(bytes) {
  if (bytes == null) return "—";
  const units = ["بايت", "ك.ب", "م.ب", "ج.ب", "ت.ب"];
  let v = Number(bytes), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + " " + units[i];
}
function humanTime(seconds) {
  if (seconds == null || !isFinite(seconds)) return "—";
  seconds = Math.round(seconds);
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
  return h ? `${h}س ${m}د` : m ? `${m}د ${s}ث` : `${s}ث`;
}
function showAlert(message, kind = "error", details = null) {
  const el = $("alert");
  el.className = "alert " + kind;
  el.textContent = message + (details && kind === "error" ? "\n" + details : "");
  el.classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (kind !== "error") setTimeout(() => el.classList.add("hidden"), 6000);
}
function hideAlert() { $("alert").classList.add("hidden"); }
async function guarded(fn) {
  hideAlert();
  try { return await fn(); } catch (err) { showAlert(err.message, "error", err.details); }
}
function stat(label, value, cls = "") {
  return `<div class="stat ${cls}"><div class="value">${esc(value)}</div><div class="label">${esc(label)}</div></div>`;
}
function remember(id) {
  const el = $(id);
  const saved = localStorage.getItem("pmv:" + id);
  if (saved && !el.value) el.value = saved;
  el.addEventListener("change", () => localStorage.setItem("pmv:" + id, el.value));
}
function setPath(id, value) {
  $(id).value = value;
  localStorage.setItem("pmv:" + id, value);
}

/* ---------------------------------------------------------------- navigation */
function showPage(name) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + name));
  if (name === "history") loadHistory();
  if (name === "settings") loadSettings();
  if (name === "backup" && state.device && !state.sources.length) loadSources();
}

/* ---------------------------------------------------------------- key */
function renderKey(key) {
  const card = $("key-card");
  $("key-info").textContent = key.exists
    ? `مفتاح التوقيع: ${key.mode === "dpapi" ? "محمي بـ Windows DPAPI" : "محمي بكلمة مرور"} — ${key.key_path}`
    : "لم يُنشأ مفتاح التوقيع بعد.";
  if (key.exists && key.unlocked) { card.classList.add("hidden"); return; }
  if (!key.exists && key.dpapi_available) {
    card.classList.add("hidden");  // created automatically with DPAPI on first backup
    return;
  }
  card.classList.remove("hidden");
  $("key-message").textContent = key.exists
    ? "أدخل كلمة مرور مفتاح التوقيع لفتحه (مطلوب لتوقيع النسخ)."
    : "أنشئ كلمة مرور (8 أحرف على الأقل) لحماية مفتاح التوقيع Ed25519 على هذا الكمبيوتر.";
}

async function submitKey() {
  await guarded(async () => {
    const key = await call("setup_key", $("key-password").value);
    $("key-password").value = "";
    renderKey(key);
    showAlert("مفتاح التوقيع جاهز.", "success");
  });
}

/* ---------------------------------------------------------------- devices */
async function loadDevices() {
  const list = $("device-list");
  list.innerHTML = '<p class="muted">جارٍ البحث…</p>';
  try {
    const devices = await call("list_devices");
    if (!devices.length) {
      list.innerHTML = '<p class="muted">لم يتم العثور على هاتف. تأكد من تفعيل تصحيح USB ثم اضغط تحديث.</p>';
      return;
    }
    list.innerHTML = devices.map((d) => `
      <div class="list-item">
        <div>
          <div class="title"><span class="status-dot ${d.authorized ? "ok" : "warn"}"></span>${esc(d.model)}</div>
          <div class="sub">${esc(d.status_ar)} — <span dir="ltr">${esc(d.serial)}</span></div>
        </div>
        <button class="btn primary" data-serial="${esc(d.serial)}" ${d.authorized ? "" : "disabled"}>
          ${state.device && state.device.serial === d.serial ? "✔ محدد" : "اختيار"}</button>
      </div>`).join("");
    list.querySelectorAll("button[data-serial]").forEach((b) => b.addEventListener("click", () => selectDevice(b.dataset.serial)));
    if (devices.length === 1 && devices[0].authorized && !state.device) selectDevice(devices[0].serial);
  } catch (err) {
    list.innerHTML = `<p class="alert error">${esc(err.message)}</p>`;
  }
}

function renderDeviceChip(device) {
  const chip = $("device-chip");
  chip.classList.add("connected");
  chip.innerHTML = `<b>${esc(device.model)}</b><br>Android ${esc(device.android_version)}<br><span dir="ltr">${esc(device.serial)}</span>`;
}

async function selectDevice(serial) {
  await guarded(async () => {
    const device = await call("select_device", serial);
    state.device = device;
    state.sources = [];
    renderDeviceChip(device);
    if (!$("backup-destination").value) setPath("backup-destination", device.suggested_destination);
    loadDevices();
    showAlert(`تم اختيار ${device.model}.`, "success");
  });
}

/* ---------------------------------------------------------------- sources & scan */
async function loadSources() {
  const box = $("source-list");
  if (!state.device) { box.innerHTML = '<p class="muted">اختر هاتفاً أولاً من صفحة الجهاز.</p>'; return; }
  box.innerHTML = '<p class="muted">جارٍ اكتشاف المجلدات…</p>';
  await guarded(async () => {
    state.sources = await call("discover_sources");
    renderSources();
  });
}

function renderSources() {
  const box = $("source-list");
  if (!state.sources.length) { box.innerHTML = '<p class="muted">لم يتم العثور على مجلدات.</p>'; return; }
  const anySelected = state.sources.some((s) => s.selected);
  box.innerHTML = state.sources.map((s, i) => {
    const checked = s.selected || (!anySelected && s.source_id === "folder:dcim");
    const broad = s.kind === "internal_storage" || s.kind === "sd_card";
    return `<label class="source ${broad ? "broad" : ""}">
      <input type="checkbox" data-index="${i}" ${checked ? "checked" : ""}>
      <div><div>${esc(s.label_ar)}</div><div class="path">${esc(s.root_path)}</div></div>
      ${s.kind === "custom" ? `<button class="remove" title="إزالة" data-remove="${esc(s.root_path)}">✖</button>` : ""}
    </label>`;
  }).join("");
  box.querySelectorAll("button[data-remove]").forEach((b) => b.addEventListener("click", async (e) => {
    e.preventDefault();
    await guarded(async () => { await call("remove_custom_folder", b.dataset.remove); await loadSources(); });
  }));
}

function selectedSourceIds() {
  return [...document.querySelectorAll("#source-list input[type=checkbox]")]
    .filter((c) => c.checked).map((c) => state.sources[Number(c.dataset.index)].source_id);
}

async function addCustomFolder() {
  await guarded(async () => {
    const source = await call("add_custom_folder", $("custom-folder").value.trim());
    state.sources = state.sources.filter((s) => s.source_id !== source.source_id).concat([source]);
    state.sources.forEach((s) => { s.selected = selectedSourceIds().includes(s.source_id) || s.source_id === source.source_id; });
    $("custom-folder").value = "";
    renderSources();
  });
}

async function startScan() {
  await guarded(async () => {
    const ids = selectedSourceIds();
    const job = await call("start_scan", ids);
    runJob(job, "فحص ملفات الهاتف", (snap) => {
      const r = snap.result;
      $("scan-card").classList.remove("hidden");
      $("scan-stats").innerHTML =
        stat("إجمالي الملفات", r.total_files) + stat("الحجم الكلي", r.total_human) +
        stat("صور", `${r.photo_count} (${r.photo_human})`) + stat("فيديو", `${r.video_count} (${r.video_human})`) +
        stat("ملفات أخرى", `${r.other_count} (${r.other_human})`) + stat("روابط رمزية متخطاة", r.symlinks_skipped);
      const wbox = $("scan-warnings-box");
      if (r.warnings_count) {
        wbox.classList.remove("hidden");
        $("scan-warnings-title").textContent = `⚠ ${r.warnings_count} تحذير أثناء الفحص (النسخة لن تُعتبر موثقة بالكامل)`;
        $("scan-warnings").innerHTML = r.warnings.map((w) =>
          `<li>${esc(w.message_ar)} ${w.phone_path ? `<span class="ltr">${esc(w.phone_path)}</span>` : ""}</li>`).join("");
      } else wbox.classList.add("hidden");
      $("backup-card").classList.toggle("hidden", r.total_files === 0);
    });
  });
}

/* ---------------------------------------------------------------- backup */
async function startBackup() {
  await guarded(async () => {
    const destination = $("backup-destination").value.trim();
    localStorage.setItem("pmv:backup-destination", destination);
    const job = await call("start_backup", destination, {
      verify_after: $("opt-verify").checked, hash_serial: $("opt-hash-serial").checked,
    });
    runJob(job, "النسخ الاحتياطي", (snap) => renderBackupResult(snap.result), true);
  });
}

function renderBackupResult(r) {
  const box = $("backup-result");
  box.classList.remove("hidden");
  let verdict = r.fully_verified
    ? '<div class="verdict ok">✔ اكتمل النسخ وتم التحقق من جميع الملفات</div>'
    : r.cancelled ? '<div class="verdict warn">⏹ أُلغي النسخ — يمكن استئنافه بنفس المجلد</div>'
    : r.interrupted ? '<div class="verdict bad">⚠ انقطع الاتصال بالهاتف — أعد التوصيل واستأنف بنفس المجلد</div>'
    : '<div class="verdict warn">⚠ اكتمل النسخ مع ملاحظات — راجع الملفات الفاشلة أو التحذيرات</div>';
  let html = verdict + '<div class="stats">' +
    stat("ملفات موثقة", `${r.verified_count} / ${r.files_total}`, "ok") +
    stat("لم تتغير (تخطي)", r.skipped_count) +
    stat("فشلت", r.failed_count, r.failed_count ? "bad" : "") +
    stat("حجم موثق", r.verified_human) + "</div>";
  if (r.verification) {
    html += `<p><b>التحقق اللاحق:</b> ${esc(r.verification.verdict_ar)}</p>`;
  }
  if (r.failed_files && r.failed_files.length) {
    html += `<details><summary>الملفات الفاشلة (${r.failed_files.length})</summary><ul>` +
      r.failed_files.map((f) => `<li><span class="ltr">${esc(f.phone_path)}</span> — ${esc(f.error)}</li>`).join("") + "</ul></details>";
  }
  html += `<div class="row"><button class="btn" data-open="${esc(r.backup_directory)}">📂 فتح مجلد النسخة</button>` +
    (r.report_path ? `<button class="btn" data-open="${esc(r.report_path)}">📄 فتح التقرير</button>` : "") + "</div>";
  box.innerHTML = html;
  bindOpenButtons(box);
  ["verify-path", "restore-path", "wipe-path", "export-source"].forEach((id) => setPath(id, r.backup_directory));
}

function bindOpenButtons(root) {
  root.querySelectorAll("button[data-open]").forEach((b) =>
    b.addEventListener("click", () => guarded(() => call("open_path", b.dataset.open))));
}

/* ---------------------------------------------------------------- verify */
async function startVerify() {
  await guarded(async () => {
    const job = await call("start_verify", $("verify-path").value.trim());
    runJob(job, "التحقق من سلامة النسخة", (snap) => {
      const r = snap.result;
      const box = $("verify-result");
      box.classList.remove("hidden");
      const cls = r.complete ? "ok" : r.intact ? "warn" : "bad";
      let html = `<div class="verdict ${cls}">${esc(r.verdict_ar)}</div><div class="stats">` +
        stat("توقيع Ed25519", r.signature_valid ? "صالح" : "غير صالح", r.signature_valid ? "ok" : "bad") +
        stat("المفتاح", r.public_key_trusted === true ? "موثوق" : r.public_key_trusted === false ? "غير موثوق" : "غير مفحوص",
             r.public_key_trusted === false ? "bad" : "") +
        stat("ملفات سليمة", `${r.ok_count} / ${r.files_total}`, "ok") +
        stat("تالفة / مفقودة", r.damaged_count, r.damaged_count ? "bad" : "") +
        stat("لم تُنسخ", r.not_backed_up_count) +
        stat("ملفات إضافية", r.extra_files.length) + "</div>";
      if (r.device) html += `<p class="muted">الهاتف: ${esc(r.device.model)} — Android ${esc(r.device.android_version)} — تاريخ النسخة: ${esc(r.backup_date)}</p>`;
      if (r.problems.length) {
        html += `<details open><summary>الملفات التي بها مشكلة (${r.problems.length})</summary><ul>` +
          r.problems.slice(0, 300).map((p) => `<li>${esc(p.status_ar)}: <span class="ltr">${esc(p.phone_path)}</span></li>`).join("") + "</ul></details>";
      }
      if (r.extra_files.length) {
        html += `<details><summary>ملفات غير موجودة في manifest (${r.extra_files.length})</summary><ul>` +
          r.extra_files.slice(0, 300).map((p) => `<li class="ltr">${esc(p)}</li>`).join("") + "</ul></details>";
      }
      if (r.report_path) html += `<div class="row"><button class="btn" data-open="${esc(r.report_path)}">📄 فتح تقرير HTML</button></div>`;
      box.innerHTML = html;
      bindOpenButtons(box);
    });
  });
}

/* ---------------------------------------------------------------- restore */
async function startRestore() {
  await guarded(async () => {
    const mode = document.querySelector("input[name=restore-mode]:checked").value;
    const conflict = document.querySelector("input[name=restore-conflict]:checked").value;
    const target = $("restore-target").value.trim();
    const msg = mode === "original"
      ? "ستتم كتابة الملفات إلى مساراتها الأصلية على الهاتف (دون استبدال أي ملف موجود). متابعة؟"
      : `ستتم كتابة الملفات إلى ${target} على الهاتف. متابعة؟`;
    if (!confirm(msg)) return;
    const job = await call("start_restore", $("restore-path").value.trim(), mode, target, conflict);
    runJob(job, "الاستعادة إلى الهاتف", (snap) => {
      const r = snap.result;
      const box = $("restore-result");
      box.classList.remove("hidden");
      const cls = r.failed ? "bad" : r.cancelled || r.interrupted ? "warn" : "ok";
      let html = `<div class="verdict ${cls}">${r.failed ? "اكتملت الاستعادة مع أخطاء" : r.cancelled ? "أُلغيت الاستعادة" : "✔ اكتملت الاستعادة"}</div>` +
        '<div class="stats">' + stat("تمت استعادتها", r.restored, "ok") + stat("موجودة مسبقاً", r.already_present) +
        stat("تعارضات متخطاة", r.conflicts) + stat("فشلت", r.failed, r.failed ? "bad" : "") + "</div>";
      if (r.outcomes.length) {
        html += `<details><summary>تفاصيل (${r.outcomes.length})</summary><ul>` +
          r.outcomes.map((o) => `<li><span class="ltr">${esc(o.target_phone_path)}</span> — ${esc(o.detail || o.status)}</li>`).join("") + "</ul></details>";
      }
      box.innerHTML = html;
    }, true);
  });
}

/* ---------------------------------------------------------------- wipe */
async function startWipePlan() {
  await guarded(async () => {
    $("wipe-result").classList.add("hidden");
    const job = await call("start_wipe_plan", $("wipe-path").value.trim());
    runJob(job, "فحص الملفات القابلة للحذف بأمان", (snap) => {
      const r = snap.result;
      $("wipe-plan-card").classList.remove("hidden");
      $("wipe-stats").innerHTML = stat("ملفات مؤكدة يمكن حذفها", r.eligible_count, "ok") +
        stat("المساحة التي ستتحرر", r.eligible_human) + stat("ستبقى على الهاتف", r.rejected_count);
      $("wipe-rejected-title").textContent = `الملفات التي لن تُحذف وأسبابها (${r.rejected_count})`;
      $("wipe-rejected").innerHTML = r.rejected.map((x) => `<li><span class="ltr">${esc(x.phone_path)}</span> — ${esc(x.reason_ar)}</li>`).join("");
      $("wipe-confirm-area").classList.toggle("hidden", r.eligible_count === 0);
    });
  });
}

async function executeWipe() {
  await guarded(async () => {
    if (!confirm("سيتم حذف الملفات المؤكدة نسخها من الهاتف نهائياً. هل أنت متأكد؟")) return;
    const job = await call("execute_wipe", $("wipe-confirm").value);
    $("wipe-confirm").value = "";
    runJob(job, "حذف الملفات المؤكدة من الهاتف", (snap) => {
      const r = snap.result;
      $("wipe-plan-card").classList.add("hidden");
      const box = $("wipe-result");
      box.classList.remove("hidden");
      let html = `<div class="verdict ${r.failed.length ? "warn" : "ok"}">تم حذف ${r.deleted_count} ملف وتحرير ${esc(r.freed_human)}</div>` +
        '<div class="stats">' + stat("محذوفة", r.deleted_count, "ok") + stat("متخطاة (تغيرت)", r.skipped.length) +
        stat("فشلت", r.failed.length, r.failed.length ? "bad" : "") + "</div>";
      const issues = r.skipped.concat(r.failed);
      if (issues.length) html += "<ul>" + issues.map((x) => `<li><span class="ltr">${esc(x.phone_path)}</span> — ${esc(x.reason_ar)}</li>`).join("") + "</ul>";
      box.innerHTML = html;
    }, true);
  });
}

/* ---------------------------------------------------------------- export */
async function startExport() {
  await guarded(async () => {
    const p1 = $("export-password").value, p2 = $("export-password2").value;
    if (p1 !== p2) throw new Error("كلمتا المرور غير متطابقتين.");
    let target = $("export-target").value.trim();
    if (!target) { target = await call("default_archive_name", $("export-source").value.trim()); $("export-target").value = target; }
    const job = await call("start_export", $("export-source").value.trim(), target, p1);
    $("export-password").value = ""; $("export-password2").value = "";
    runJob(job, "تصدير أرشيف مشفّر", (snap) => {
      const r = snap.result;
      const box = $("export-result");
      box.classList.remove("hidden");
      box.innerHTML = `<div class="verdict ok">✔ تم إنشاء الأرشيف المشفّر والتحقق منه (${r.files} ملف، ${esc(r.size_human)})</div>
        <p class="ltr">${esc(r.archive_path)}</p>`;
    });
  });
}

/* ---------------------------------------------------------------- history & settings */
const HISTORY_LABELS = { backup: "💾 نسخ احتياطي", verify: "🛡️ تحقق", restore: "♻️ استعادة", wipe: "🧹 حذف آمن" };
async function loadHistory() {
  await guarded(async () => {
    const items = await call("get_history");
    const box = $("history-list");
    if (!items.length) { box.innerHTML = '<p class="muted">لا توجد عمليات بعد.</p>'; return; }
    box.innerHTML = items.map((h) => {
      let detail = "";
      if (h.kind === "backup") detail = `${h.verified}/${h.files} موثق، ${h.failed} فشل ${h.fully_verified ? "✔" : "⚠"}`;
      if (h.kind === "verify") detail = h.complete ? "سليمة بالكامل ✔" : h.intact ? "سليمة مع ملفات لم تُنسخ" : `مشكلة: ${h.damaged} ملف ✖`;
      if (h.kind === "restore") detail = `${h.restored} مستعاد، ${h.failed} فشل`;
      if (h.kind === "wipe") detail = `${h.deleted} محذوف، ${humanSize(h.freed_bytes)} محررة`;
      return `<div class="list-item"><div><div class="title">${HISTORY_LABELS[h.kind] || esc(h.kind)} — ${esc(detail)}</div>
        <div class="sub ltr">${esc(h.backup_directory || "")}</div></div>
        <div class="sub">${esc(new Date(h.time).toLocaleString("ar"))}</div></div>`;
    }).join("");
  });
}

async function loadSettings() {
  await guarded(async () => {
    const s = await call("get_settings");
    $("set-destination").value = s.default_destination;
    $("set-retries").value = s.max_retries;
    $("set-restore-folder").value = s.restore_target_folder;
    $("set-verify").checked = s.verify_after_backup;
    $("set-hash-serial").checked = s.hash_serial;
    $("set-media-scan").checked = s.media_scan_after_changes;
    renderKey(await call("key_status"));
  });
}

async function saveSettings() {
  await guarded(async () => {
    const s = await call("save_settings", {
      default_destination: $("set-destination").value.trim(),
      max_retries: Number($("set-retries").value || 3),
      restore_target_folder: $("set-restore-folder").value.trim() || "/sdcard/Restored",
      verify_after_backup: $("set-verify").checked,
      hash_serial: $("set-hash-serial").checked,
      media_scan_after_changes: $("set-media-scan").checked,
    });
    applySettings(s);
    showAlert("تم حفظ الإعدادات.", "success");
  });
}

function applySettings(s) {
  $("opt-verify").checked = s.verify_after_backup;
  $("opt-hash-serial").checked = s.hash_serial;
  $("restore-target").value = s.restore_target_folder;
  document.querySelector(`input[name=restore-conflict][value=${s.restore_conflict_policy}]`).checked = true;
}

/* ---------------------------------------------------------------- jobs */
function runJob(job, title, onDone, pausable = false) {
  state.job = job;
  state.onJobDone = onDone;
  $("job-title").textContent = title + "…";
  $("job-pause").classList.toggle("hidden", !pausable);
  $("job-pause").textContent = "⏸ إيقاف مؤقت";
  $("job-cancel").disabled = false;
  $("job-overlay").classList.remove("hidden");
  renderJob(job);
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollJob, 400);
}

async function pollJob() {
  if (!state.job) return;
  let snap;
  try { snap = await call("get_job", state.job.id); } catch (err) { return; }
  state.job = snap;
  renderJob(snap);
  if (["done", "error", "cancelled"].includes(snap.state)) {
    clearInterval(state.pollTimer);
    $("job-overlay").classList.add("hidden");
    const callback = state.onJobDone;
    state.job = null;
    if (snap.state === "error") showAlert(snap.error, "error", null);
    else if (snap.result && callback) callback(snap);
    else if (snap.state === "cancelled") showAlert("أُلغيت العملية.", "info");
  }
}

function renderJob(snap) {
  const p = snap.progress || {};
  const bar = $("job-bar");
  let pct = null, line = p.message || "", current = "";
  if (p.files_total != null) {
    if (p.bytes_total) pct = (p.bytes_processed ?? p.bytes_done ?? 0) / p.bytes_total;
    else if (p.files_total) pct = p.files_done / p.files_total;
    line = `${p.phase === "verify" ? "التحقق: " : ""}${p.files_done} / ${p.files_total} ملف`;
    if (p.bytes_total) line += ` — ${humanSize(p.bytes_processed ?? p.bytes_done)} من ${humanSize(p.bytes_total)}`;
    if (p.speed_bytes_per_second) line += ` — ${humanSize(p.speed_bytes_per_second)}/ث — المتبقي ${humanTime(p.eta_seconds)}`;
    if (p.failed_count) line += ` — فشل ${p.failed_count}`;
    current = p.current_phone_path || p.current_relative_path || p.current || "";
  }
  if (pct == null) { bar.classList.add("indeterminate"); }
  else { bar.classList.remove("indeterminate"); bar.style.width = Math.min(100, pct * 100).toFixed(1) + "%"; }
  if (snap.state === "paused") line = "⏸ متوقف مؤقتاً — " + line;
  $("job-line").textContent = line;
  $("job-current").textContent = current;
  $("job-pause").textContent = snap.state === "paused" ? "▶ استئناف" : "⏸ إيقاف مؤقت";
}

async function togglePause() {
  if (!state.job) return;
  await guarded(() => call(state.job.state === "paused" ? "resume_job" : "pause_job", state.job.id));
}
async function cancelJob() {
  if (!state.job) return;
  $("job-cancel").disabled = true;
  await guarded(() => call("cancel_job", state.job.id));
}

/* ---------------------------------------------------------------- boot */
async function chooseFolder(targetId) {
  await guarded(async () => {
    const folder = await call("choose_folder");
    if (folder) setPath(targetId, folder);
  });
}

async function boot() {
  await bridgeReady();
  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  document.querySelectorAll(".folder-btn").forEach((b) => b.addEventListener("click", () => chooseFolder(b.dataset.target)));
  ["backup-destination", "verify-path", "restore-path", "wipe-path", "export-source"].forEach(remember);
  $("refresh-devices").addEventListener("click", loadDevices);
  $("reload-sources").addEventListener("click", loadSources);
  $("add-custom").addEventListener("click", addCustomFolder);
  $("start-scan").addEventListener("click", startScan);
  $("start-backup").addEventListener("click", startBackup);
  $("start-verify").addEventListener("click", startVerify);
  $("start-restore").addEventListener("click", startRestore);
  $("start-wipe-plan").addEventListener("click", startWipePlan);
  $("execute-wipe").addEventListener("click", executeWipe);
  $("start-export").addEventListener("click", startExport);
  $("refresh-history").addEventListener("click", loadHistory);
  $("save-settings").addEventListener("click", saveSettings);
  $("key-submit").addEventListener("click", submitKey);
  $("key-password").addEventListener("keydown", (e) => { if (e.key === "Enter") submitKey(); });
  $("job-pause").addEventListener("click", togglePause);
  $("job-cancel").addEventListener("click", cancelJob);

  try {
    const info = await call("app_info");
    state.info = info;
    $("app-version").textContent = "v" + info.version;
    $("demo-badge").classList.toggle("hidden", !info.demo);
    $("wipe-phrase").textContent = info.wipe_phrases[0];
    $("adb-info").textContent = info.adb_error ? info.adb_error : info.adb_path ? `ADB: ${info.adb_path}` : "";
    if (!info.can_choose_folder) document.querySelectorAll(".folder-btn").forEach((b) => b.classList.add("hidden"));
    renderKey(info.key);
    applySettings(await call("get_settings"));
    const current = await call("current_device");
    if (current) { state.device = current; renderDeviceChip(current); }
    const active = await call("active_job");
    if (active) runJob(active, "عملية قيد التنفيذ", null, active.kind === "backup");
  } catch (err) { showAlert(err.message); }
  loadDevices();
}

document.addEventListener("DOMContentLoaded", boot);
