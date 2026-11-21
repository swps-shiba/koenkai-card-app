"use strict";
/* 後援会カード管理アプリ 骨格 v0.1
   注意: この段階ではパスコードは画面ロック用。
   データの暗号化（AES-GCM）は設計ステップ3で本適用する。 */

const $ = (sel) => document.querySelector(sel);

/* ---------- IndexedDB ---------- */
const DB_NAME = "koenkai-card-app";
const DB_VERSION = 1;
let db = null;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const d = req.result;
      if (!d.objectStoreNames.contains("cards")) d.createObjectStore("cards", { keyPath: "id" });
      if (!d.objectStoreNames.contains("meta")) d.createObjectStore("meta", { keyPath: "key" });
    };
    req.onsuccess = () => { db = req.result; resolve(); };
    req.onerror = () => reject(req.error);
  });
}
function idbGetAll(store) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(store, "readonly").objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}
function idbGet(store, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(store, "readonly").objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
function idbPut(store, value) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(store, "readwrite").objectStore(store).put(value);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}
function idbDelete(store, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(store, "readwrite").objectStore(store).delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/* ---------- ユーティリティ ---------- */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}
function fmtDateTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function toLocalInput(iso) {
  const d = iso ? new Date(iso) : new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
function b64encode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64decode(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

/* ---------- パスコード（PBKDF2） ---------- */
async function deriveHash(passcode, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passcode), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 150000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return bits;
}
async function setupPasscode(passcode) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveHash(passcode, salt);
  await idbPut("meta", { key: "passcode", salt: b64encode(salt), hash: b64encode(hash) });
}
async function verifyPasscode(passcode) {
  const rec = await idbGet("meta", "passcode");
  if (!rec) return false;
  const hash = await deriveHash(passcode, b64decode(rec.salt));
  return b64encode(hash) === rec.hash;
}

/* ---------- 状態 ---------- */
let cards = [];
let viewList = [];
let currentId = null;
let editingId = null;
let editingRecordId = null;
let pendingFrontPhoto = null;
let pendingBackPhoto = null;
let setupMode = false;
let hiddenAt = null;

function sortedCards() {
  return [...cards].sort((a, b) =>
    (a.furigana || a.name || "").localeCompare(b.furigana || b.name || "", "ja"));
}
function currentCard() {
  return cards.find((c) => c.id === currentId) || null;
}
async function persistCard(card) {
  card.updatedAt = new Date().toISOString();
  await idbPut("cards", card);
  const i = cards.findIndex((c) => c.id === card.id);
  if (i >= 0) cards[i] = card; else cards.push(card);
}

/* ---------- 画面切替 ---------- */
function showView(id) {
  for (const v of ["lockView", "listView", "detailView", "formView"]) {
    $("#" + v).classList.toggle("hidden", v !== id);
  }
}
function lockApp() {
  currentId = null;
  $("#lockInput").value = "";
  $("#lockError").textContent = "";
  showView("lockView");
  $("#lockInput").focus();
}

/* ---------- ロック画面 ---------- */
async function initLock() {
  const rec = await idbGet("meta", "passcode");
  setupMode = !rec;
  $("#lockMessage").textContent = setupMode
    ? "最初にパスコードを決めてください（4桁以上）"
    : "パスコードを入力してください";
  $("#lockInput2").classList.toggle("hidden", !setupMode);
  $("#lockButton").textContent = setupMode ? "設定して始める" : "開く";
  showView("lockView");
}
$("#lockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const v1 = $("#lockInput").value.trim();
  const err = $("#lockError");
  err.textContent = "";
  if (setupMode) {
    if (v1.length < 4) { err.textContent = "パスコードは4文字以上にしてください。"; return; }
    if (v1 !== $("#lockInput2").value.trim()) { err.textContent = "確認用と一致しません。"; return; }
    await setupPasscode(v1);
    setupMode = false;
    enterApp();
  } else {
    if (await verifyPasscode(v1)) enterApp();
    else err.textContent = "パスコードが違います。";
  }
});
$("#lockNowBtn").addEventListener("click", lockApp);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { hiddenAt = Date.now(); return; }
  /* 3分以上離れていたら自動ロック（ロック画面表示中は除く） */
  if (hiddenAt && Date.now() - hiddenAt > 180000 && $("#lockView").classList.contains("hidden")) {
    lockApp();
  }
  hiddenAt = null;
});

function enterApp() {
  renderList();
  showView("listView");
}

/* ---------- 一覧 ---------- */
function renderList() {
  const q = $("#searchInput").value.trim();
  const all = sortedCards();
  viewList = q
    ? all.filter((c) => [c.name, c.furigana, c.address, c.zip].some((f) => (f || "").includes(q)))
    : all;
  $("#cardCount").textContent = `${viewList.length} 件`;
  $("#emptyMessage").classList.toggle("hidden", cards.length !== 0);
  const list = $("#cardList");
  list.innerHTML = "";
  for (const c of viewList) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "card-item";
    const thumb = c.frontPhoto
      ? `<img src="${c.frontPhoto}" alt="">`
      : `<span class="thumb-empty">🗂️</span>`;
    btn.innerHTML = `${thumb}<span><span class="name">${esc(c.name)} 様</span>
      <span class="sub">${esc(c.furigana || "")}</span><br>
      <span class="sub">${esc(c.address || "")}</span></span>`;
    btn.addEventListener("click", () => openDetail(c.id));
    list.appendChild(btn);
  }
}
$("#searchInput").addEventListener("input", renderList);
$("#addCardBtn").addEventListener("click", () => openForm(null));

/* ---------- 詳細 ---------- */
function openDetail(id) {
  currentId = id;
  renderDetail(false);
  showView("detailView");
}
function detailIndex() {
  return viewList.findIndex((c) => c.id === currentId);
}
function renderDetail(flipped) {
  const c = currentCard();
  if (!c) { renderList(); showView("listView"); return; }
  const idx = detailIndex();
  $("#detailCounter").textContent = idx >= 0 ? `${idx + 1} / ${viewList.length}` : "";
  $("#prevCardBtn").disabled = idx <= 0;
  $("#nextCardBtn").disabled = idx < 0 || idx >= viewList.length - 1;
  $("#flipInner").classList.toggle("flipped", !!flipped);
  const fi = $("#frontImg"), bi = $("#backImg");
  fi.classList.toggle("hidden", !c.frontPhoto);
  bi.classList.toggle("hidden", !c.backPhoto);
  if (c.frontPhoto) fi.src = c.frontPhoto;
  if (c.backPhoto) bi.src = c.backPhoto;
  $("#frontInfo").classList.toggle("hidden", !!flipped);
  $("#backInfo").classList.toggle("hidden", !flipped);
  renderFrontInfo(c);
  renderBackInfo(c);
}
function row(label, value) {
  return value ? `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>` : "";
}
function renderFrontInfo(c) {
  const mapsUrl = c.address
    ? `https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent((c.zip ? "〒" + c.zip + " " : "") + c.address)}`
    : "";
  const actions = [];
  if (mapsUrl) actions.push(`<a class="solid" href="${mapsUrl}" target="_blank" rel="noopener">🧭 住所へナビ</a>`);
  if (c.mobile) actions.push(`<a href="tel:${esc(c.mobile.replace(/[^0-9+]/g, ""))}">📱 携帯に電話</a>`);
  if (c.phone) actions.push(`<a href="tel:${esc(c.phone.replace(/[^0-9+]/g, ""))}">☎️ 電話をかける</a>`);
  if (c.email) actions.push(`<a href="mailto:${esc(c.email)}">✉️ メール</a>`);
  $("#frontInfo").innerHTML = `
    <div class="furigana">${esc(c.furigana || "")}</div>
    <h2>${esc(c.name)} 様${c.age ? `（${esc(c.age)}歳）` : ""}</h2>
    <dl>
      ${row("郵便番号", c.zip ? "〒" + c.zip : "")}
      ${row("ご住所", c.address)}
      ${row("電話番号", c.phone)}
      ${row("携帯番号", c.mobile)}
      ${row("メールアドレス", c.email)}
      ${row("担当 郵便局", c.staffOffice)}
      ${row("担当者", c.staffName)}
    </dl>
    ${actions.length ? `<div class="action-row">${actions.join("")}</div>` : ""}`;
}
function renderBackInfo(c) {
  const records = [...(c.records || [])].sort((a, b) => (a.datetime < b.datetime ? 1 : -1));
  const items = records.map((r) => `
    <button type="button" class="record-item" data-record-id="${esc(r.id)}">
      <span class="r-main">
        <span class="r-head"><span class="r-type">${esc(r.type)}</span>${esc(fmtDateTime(r.datetime))}${r.staff ? " ・ " + esc(r.staff) : ""}</span>
        <span class="r-content">${esc(r.content || "")}</span>
      </span>
      ${r.confirm
        ? `<span class="confirm-check" data-confirm-id="${esc(r.id)}" title="確認の詳細">✓</span>`
        : `<span class="confirm-none">未確認</span>`}
    </button>`).join("");
  $("#backInfo").innerHTML = `
    <h2>ご紹介者様</h2>
    <div class="furigana">${esc(c.introFurigana || "")}</div>
    <dl>
      ${row("お名前", c.introName)}
      ${row("郵便局名 又は ご住所", c.introPlace)}
      ${row("電話番号", c.introPhone)}
      ${row("本人様との関係", c.introRelation ? c.introRelation + (c.introRelationNote ? `（${c.introRelationNote}）` : "") : "")}
      ${row("参考情報", c.introNote)}
    </dl>
    <h2 style="margin-top:18px;">訪問・電話の記録</h2>
    <div class="records">${items || '<p class="sub">まだ記録がありません。</p>'}</div>
    <button type="button" id="addRecordBtn" class="primary-btn add-record-btn">＋ 記録を追加</button>`;
  $("#addRecordBtn").addEventListener("click", () => openRecordDialog(null));
  for (const el of document.querySelectorAll("[data-record-id]")) {
    el.addEventListener("click", (e) => {
      const confirmEl = e.target.closest("[data-confirm-id]");
      if (confirmEl) { e.stopPropagation(); showConfirmDetail(confirmEl.dataset.confirmId); return; }
      openRecordDialog(el.dataset.recordId);
    });
  }
}
$("#flipArea").addEventListener("click", () => {
  renderDetail(!$("#flipInner").classList.contains("flipped"));
});
$("#prevCardBtn").addEventListener("click", () => stepCard(-1));
$("#nextCardBtn").addEventListener("click", () => stepCard(1));
function stepCard(dir) {
  const idx = detailIndex();
  if (idx < 0) return;
  const next = viewList[idx + dir];
  if (!next) return;
  currentId = next.id;
  renderDetail(false);
}
$("#backToListBtn").addEventListener("click", () => { renderList(); showView("listView"); });
$("#editCardBtn").addEventListener("click", () => openForm(currentId));
$("#deleteCardBtn").addEventListener("click", async () => {
  const c = currentCard();
  if (!c) return;
  if (!confirm(`「${c.name} 様」のカードを削除しますか？`)) return;
  await idbDelete("cards", c.id);
  cards = cards.filter((x) => x.id !== c.id);
  currentId = null;
  renderList();
  showView("listView");
});

/* ---------- 活動記録 ---------- */
function openRecordDialog(recordId) {
  const c = currentCard();
  if (!c) return;
  editingRecordId = recordId;
  const r = recordId ? (c.records || []).find((x) => x.id === recordId) : null;
  $("#recordDialogTitle").textContent = r ? "記録を編集" : "記録を追加";
  $("#rDateTime").value = toLocalInput(r ? r.datetime : new Date().toISOString());
  $("#rType").value = r ? r.type : "訪問";
  $("#rContent").value = r ? r.content || "" : "";
  $("#rStaff").value = r ? r.staff || "" : (c.staffName || "");
  $("#rConfirmed").checked = !!(r && r.confirm);
  $("#rConfirmName").value = r && r.confirm ? r.confirm.name || "" : "";
  $("#rConfirmDate").value = r && r.confirm ? toLocalInput(r.confirm.datetime) : toLocalInput(new Date().toISOString());
  $("#recordDeleteBtn").classList.toggle("hidden", !r);
  $("#recordDialog").showModal();
}
$("#recordCancelBtn").addEventListener("click", () => $("#recordDialog").close());
$("#recordDeleteBtn").addEventListener("click", async () => {
  const c = currentCard();
  if (!c || !editingRecordId) return;
  if (!confirm("この記録を削除しますか？")) return;
  c.records = (c.records || []).filter((x) => x.id !== editingRecordId);
  await persistCard(c);
  $("#recordDialog").close();
  renderDetail(true);
});
$("#recordForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const c = currentCard();
  if (!c) return;
  const confirmed = $("#rConfirmed").checked;
  const record = {
    id: editingRecordId || uid(),
    datetime: new Date($("#rDateTime").value).toISOString(),
    type: $("#rType").value,
    content: $("#rContent").value.trim(),
    staff: $("#rStaff").value.trim(),
    confirm: confirmed
      ? { name: $("#rConfirmName").value.trim(), datetime: new Date($("#rConfirmDate").value || Date.now()).toISOString() }
      : null,
  };
  c.records = c.records || [];
  const i = c.records.findIndex((x) => x.id === record.id);
  if (i >= 0) c.records[i] = record; else c.records.push(record);
  await persistCard(c);
  $("#recordDialog").close();
  renderDetail(true);
});
function showConfirmDetail(recordId) {
  const c = currentCard();
  const r = c && (c.records || []).find((x) => x.id === recordId);
  if (!r || !r.confirm) return;
  $("#confirmDetailText").textContent =
    `確認した人：${r.confirm.name || "（名前なし）"}\n確認した日時：${fmtDateTime(r.confirm.datetime)}`;
  $("#confirmDialog").showModal();
}
$("#confirmCloseBtn").addEventListener("click", () => $("#confirmDialog").close());

/* ---------- 登録・編集フォーム ---------- */
function openForm(id) {
  editingId = id;
  const c = id ? cards.find((x) => x.id === id) : null;
  $("#formTitle").textContent = c ? "カードを編集" : "カード登録";
  $("#formError").textContent = "";
  $("#zipStatus").textContent = "";
  const set = (sel, v) => { $(sel).value = v || ""; };
  set("#fFurigana", c && c.furigana); set("#fName", c && c.name); set("#fAge", c && c.age);
  set("#fZip", c && c.zip); set("#fAddress", c && c.address);
  set("#fPhone", c && c.phone); set("#fMobile", c && c.mobile); set("#fEmail", c && c.email);
  set("#fIntroFurigana", c && c.introFurigana); set("#fIntroName", c && c.introName);
  set("#fIntroPlace", c && c.introPlace); set("#fIntroPhone", c && c.introPhone);
  set("#fIntroRelation", c && c.introRelation); set("#fIntroRelationNote", c && c.introRelationNote);
  set("#fIntroNote", c && c.introNote);
  set("#fStaffOffice", c && c.staffOffice); set("#fStaffName", c && c.staffName);
  $("#fFrontPhoto").value = ""; $("#fBackPhoto").value = "";
  pendingFrontPhoto = c ? c.frontPhoto : null;
  pendingBackPhoto = c ? c.backPhoto : null;
  updatePreview("#fFrontPreview", pendingFrontPhoto);
  updatePreview("#fBackPreview", pendingBackPhoto);
  showView("formView");
}
function updatePreview(sel, dataUrl) {
  const img = $(sel);
  img.classList.toggle("hidden", !dataUrl);
  if (dataUrl) img.src = dataUrl;
}
/* ---------- 写真の取り込み（四隅の自動検出＋手動補正＋台形補正） ---------- */
let cropState = null; // { img, previewSel, setter, corners: [TL, TR, BR, BL]（画像実寸px） }

function readPhoto(input, previewSel, setter) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const img = new Image();
    img.onload = () => openCrop(img, previewSel, setter);
    img.src = reader.result;
  };
  reader.readAsDataURL(file);
  input.value = "";
}
$("#fFrontPhoto").addEventListener("change", (e) =>
  readPhoto(e.target, "#fFrontPreview", (d) => { pendingFrontPhoto = d; }));
$("#fBackPhoto").addEventListener("change", (e) =>
  readPhoto(e.target, "#fBackPreview", (d) => { pendingBackPhoto = d; }));

function imgW(img) { return img.naturalWidth || img.width; }
function imgH(img) { return img.naturalHeight || img.height; }

function defaultCorners(img) {
  const mx = imgW(img) * 0.06, my = imgH(img) * 0.06;
  return [
    { x: mx, y: my },
    { x: imgW(img) - mx, y: my },
    { x: imgW(img) - mx, y: imgH(img) - my },
    { x: mx, y: imgH(img) - my },
  ];
}

function openCrop(img, previewSel, setter) {
  cropState = { img, previewSel, setter, corners: defaultCorners(img) };
  $("#cropImg").src = img.src;
  $("#cropStatus").textContent = "カードの四隅を検出しています…";
  showView("cropView");
  requestAnimationFrame(() => { layoutCropOverlay(); detectCorners(); });
}

function cropScale() {
  const rect = $("#cropImg").getBoundingClientRect();
  return { rect, sx: imgW(cropState.img) / rect.width, sy: imgH(cropState.img) / rect.height };
}

function layoutCropOverlay() {
  if (!cropState) return;
  const { rect, sx, sy } = cropScale();
  if (!rect.width) return;
  const svg = $("#cropOverlay");
  svg.setAttribute("viewBox", `0 0 ${rect.width} ${rect.height}`);
  $("#cropPoly").setAttribute("points", cropState.corners.map((p) => `${p.x / sx},${p.y / sy}`).join(" "));
  svg.querySelectorAll(".crop-handle").forEach((h, i) => {
    h.setAttribute("cx", cropState.corners[i].x / sx);
    h.setAttribute("cy", cropState.corners[i].y / sy);
  });
}
window.addEventListener("resize", layoutCropOverlay);

let dragCorner = -1;
$("#cropOverlay").addEventListener("pointerdown", (e) => {
  if (!e.target.classList || !e.target.classList.contains("crop-handle")) return;
  dragCorner = Number(e.target.dataset.corner);
  e.preventDefault();
  $("#cropOverlay").setPointerCapture(e.pointerId);
});
$("#cropOverlay").addEventListener("pointermove", (e) => {
  if (dragCorner < 0 || !cropState) return;
  const { rect, sx, sy } = cropScale();
  cropState.corners[dragCorner] = {
    x: Math.min(Math.max((e.clientX - rect.left) * sx, 0), imgW(cropState.img)),
    y: Math.min(Math.max((e.clientY - rect.top) * sy, 0), imgH(cropState.img)),
  };
  layoutCropOverlay();
});
for (const ev of ["pointerup", "pointercancel"]) {
  $("#cropOverlay").addEventListener(ev, () => { dragCorner = -1; });
}

/* OpenCV.js は検出専用に遅延読み込みする。読み込めなくても手動調整で続けられる。 */
let openCvPromise = null;
function loadOpenCV() {
  if (window.cv && window.cv.Mat) return Promise.resolve(window.cv);
  if (openCvPromise) return openCvPromise;
  openCvPromise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("opencv timeout")), 25000);
    const script = document.createElement("script");
    script.src = "https://docs.opencv.org/4.8.0/opencv.js";
    script.async = true;
    script.onload = () => {
      const cv = window.cv;
      if (!cv) { clearTimeout(timer); reject(new Error("opencv missing")); return; }
      if (cv.Mat) { clearTimeout(timer); resolve(cv); return; }
      cv.onRuntimeInitialized = () => { clearTimeout(timer); resolve(cv); };
    };
    script.onerror = () => { clearTimeout(timer); reject(new Error("opencv load failed")); };
    document.head.appendChild(script);
  });
  return openCvPromise;
}

function orderCorners(pts) {
  const bySum = [...pts].sort((a, b) => (a.x + a.y) - (b.x + b.y));
  const byDiff = [...pts].sort((a, b) => (a.x - a.y) - (b.x - b.y));
  return [bySum[0], byDiff[byDiff.length - 1], bySum[bySum.length - 1], byDiff[0]]; // TL, TR, BR, BL
}

async function detectCorners() {
  if (!cropState) return;
  const status = $("#cropStatus");
  try {
    const cv = await loadOpenCV();
    const found = detectWithOpenCV(cv, cropState.img);
    if (!cropState) return;
    if (found) {
      cropState.corners = found;
      status.textContent = "四隅を検出しました。ずれているときは丸をドラッグして直してください。";
    } else {
      status.textContent = "自動検出できませんでした。丸をドラッグして四隅を合わせてください。";
    }
  } catch (e) {
    if (cropState) status.textContent = "自動検出は使えませんでした（通信環境）。丸をドラッグして四隅を合わせてください。";
  }
  layoutCropOverlay();
}

function detectWithOpenCV(cv, img) {
  const maxDim = 800;
  const scale = Math.min(1, maxDim / Math.max(imgW(img), imgH(img)));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(imgW(img) * scale);
  canvas.height = Math.round(imgH(img) * scale);
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  let src, gray, blur, edges, kernel, contours, hierarchy;
  try {
    src = cv.imread(canvas);
    gray = new cv.Mat(); cv.cvtColor(src, gray, cv.COLOR_RGBA2GRAY, 0);
    blur = new cv.Mat(); cv.GaussianBlur(gray, blur, new cv.Size(5, 5), 0, 0, cv.BORDER_DEFAULT);
    edges = new cv.Mat(); cv.Canny(blur, edges, 50, 150);
    kernel = cv.getStructuringElement(cv.MORPH_RECT, new cv.Size(5, 5));
    cv.dilate(edges, edges, kernel, new cv.Point(-1, -1), 1, cv.BORDER_CONSTANT, cv.morphologyDefaultBorderValue());
    contours = new cv.MatVector(); hierarchy = new cv.Mat();
    cv.findContours(edges, contours, hierarchy, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE);
    let best = null, bestArea = 0;
    for (let i = 0; i < contours.size(); i++) {
      const cnt = contours.get(i);
      const area = cv.contourArea(cnt);
      if (area > bestArea) { bestArea = area; best = cnt; }
    }
    if (!best || bestArea < canvas.width * canvas.height * 0.15) return null;
    const peri = cv.arcLength(best, true);
    const approx = new cv.Mat();
    cv.approxPolyDP(best, approx, 0.02 * peri, true);
    let pts = null;
    if (approx.rows === 4) {
      pts = [];
      for (let i = 0; i < 4; i++) {
        pts.push({ x: approx.data32S[i * 2] / scale, y: approx.data32S[i * 2 + 1] / scale });
      }
    }
    approx.delete();
    return pts ? orderCorners(pts) : null;
  } catch (e) {
    return null;
  } finally {
    for (const m of [src, gray, blur, edges, kernel, contours, hierarchy]) {
      if (m) { try { m.delete(); } catch (e) {} }
    }
  }
}

/* 透視変換（ホモグラフィ＋三角形メッシュ描画） */
function solveLinear(A, b) {
  const n = b.length;
  const M = A.map((row, i) => [...row, b[i]]);
  for (let col = 0, row = 0; col < n && row < n; col++, row++) {
    let pivot = row;
    for (let r = row + 1; r < n; r++) if (Math.abs(M[r][col]) > Math.abs(M[pivot][col])) pivot = r;
    const tmp = M[row]; M[row] = M[pivot]; M[pivot] = tmp;
    const div = M[row][col] || 1e-12;
    for (let j = col; j <= n; j++) M[row][j] /= div;
    for (let r = 0; r < n; r++) {
      if (r === row) continue;
      const factor = M[r][col];
      if (!factor) continue;
      for (let j = col; j <= n; j++) M[r][j] -= factor * M[row][j];
    }
  }
  return M.map((row) => row[n]);
}
function computeHomography(src, dst) {
  const A = [], b = [];
  for (let i = 0; i < 4; i++) {
    const { x, y } = src[i]; const u = dst[i].x, v = dst[i].y;
    A.push([x, y, 1, 0, 0, 0, -u * x, -u * y]); b.push(u);
    A.push([0, 0, 0, x, y, 1, -v * x, -v * y]); b.push(v);
  }
  const h = solveLinear(A, b);
  return [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], 1];
}
function applyH(H, x, y) {
  const w = H[6] * x + H[7] * y + H[8];
  return { x: (H[0] * x + H[1] * y + H[2]) / w, y: (H[3] * x + H[4] * y + H[5]) / w };
}
function affineFromTriangles(f0, f1, f2, t0, t1, t2) {
  const det = f0.x * (f1.y - f2.y) - f0.y * (f1.x - f2.x) + (f1.x * f2.y - f2.x * f1.y);
  if (!det) return null;
  const inv = [
    [(f1.y - f2.y) / det, (f2.y - f0.y) / det, (f0.y - f1.y) / det],
    [(f2.x - f1.x) / det, (f0.x - f2.x) / det, (f1.x - f0.x) / det],
    [(f1.x * f2.y - f2.x * f1.y) / det, (f2.x * f0.y - f0.x * f2.y) / det, (f0.x * f1.y - f1.x * f0.y) / det],
  ];
  const px = inv.map((row) => row[0] * t0.x + row[1] * t1.x + row[2] * t2.x);
  const py = inv.map((row) => row[0] * t0.y + row[1] * t1.y + row[2] * t2.y);
  return { a: px[0], b: px[1], e: px[2], c: py[0], d: py[1], f: py[2] };
}
function drawTri(ctx, img, s0, s1, s2, d0, d1, d2) {
  const t = affineFromTriangles(s0, s1, s2, d0, d1, d2);
  if (!t) return;
  const cx = (d0.x + d1.x + d2.x) / 3, cy = (d0.y + d1.y + d2.y) / 3;
  const ex = (p) => ({ x: cx + (p.x - cx) * 1.03, y: cy + (p.y - cy) * 1.03 });
  const e0 = ex(d0), e1 = ex(d1), e2 = ex(d2);
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(e0.x, e0.y); ctx.lineTo(e1.x, e1.y); ctx.lineTo(e2.x, e2.y); ctx.closePath();
  ctx.clip();
  ctx.setTransform(t.a, t.c, t.b, t.d, t.e, t.f);
  ctx.drawImage(img, 0, 0);
  ctx.restore();
}
function warpToCanvas(img, corners) {
  const [tl, tr, br, bl] = corners;
  const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  let outW = Math.round(Math.max(dist(tl, tr), dist(bl, br)));
  let outH = Math.round(Math.max(dist(tl, bl), dist(tr, br)));
  const s = Math.min(1, 1400 / Math.max(outW, outH));
  outW = Math.max(2, Math.round(outW * s)); outH = Math.max(2, Math.round(outH * s));
  const canvas = document.createElement("canvas");
  canvas.width = outW; canvas.height = outH;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const dst = [{ x: 0, y: 0 }, { x: outW, y: 0 }, { x: outW, y: outH }, { x: 0, y: outH }];
  const H = computeHomography(dst, corners); // 出力px → 入力px
  const cols = 24, rows = 32;
  for (let gy = 0; gy < rows; gy++) {
    for (let gx = 0; gx < cols; gx++) {
      const x0 = (gx / cols) * outW, x1 = ((gx + 1) / cols) * outW;
      const y0 = (gy / rows) * outH, y1 = ((gy + 1) / rows) * outH;
      const p00 = applyH(H, x0, y0), p10 = applyH(H, x1, y0), p11 = applyH(H, x1, y1), p01 = applyH(H, x0, y1);
      drawTri(ctx, img, p00, p10, p01, { x: x0, y: y0 }, { x: x1, y: y0 }, { x: x0, y: y1 });
      drawTri(ctx, img, p10, p11, p01, { x: x1, y: y0 }, { x: x1, y: y1 }, { x: x0, y: y1 });
    }
  }
  return canvas;
}

function closeCrop() { cropState = null; showView("formView"); }
$("#cropCancelBtn").addEventListener("click", closeCrop);
$("#cropApplyBtn").addEventListener("click", () => {
  if (!cropState) return;
  const canvas = warpToCanvas(cropState.img, cropState.corners);
  if (canvas) {
    const dataUrl = canvas.toDataURL("image/jpeg", 0.85);
    cropState.setter(dataUrl);
    updatePreview(cropState.previewSel, dataUrl);
  }
  closeCrop();
});
$("#cropRawBtn").addEventListener("click", () => {
  if (!cropState) return;
  const img = cropState.img;
  const scale = Math.min(1, 1600 / Math.max(imgW(img), imgH(img)));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(imgW(img) * scale);
  canvas.height = Math.round(imgH(img) * scale);
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const dataUrl = canvas.toDataURL("image/jpeg", 0.85);
    cropState.setter(dataUrl);
    updatePreview(cropState.previewSel, dataUrl);
  }
  closeCrop();
});
$("#cropRedetectBtn").addEventListener("click", () => {
  if (!cropState) return;
  cropState.corners = defaultCorners(cropState.img);
  layoutCropOverlay();
  $("#cropStatus").textContent = "カードの四隅を検出しています…";
  detectCorners();
});
$("#cancelFormBtn").addEventListener("click", () => {
  if (editingId) { currentId = editingId; renderDetail(false); showView("detailView"); }
  else { renderList(); showView("listView"); }
});

/* 郵便番号 → 住所（zipcloud） */
async function lookupZip() {
  const zip = $("#fZip").value.replace(/[^0-9]/g, "");
  const status = $("#zipStatus");
  if (zip.length !== 7) { status.textContent = "郵便番号は7桁で入力してください。"; return; }
  status.textContent = "検索中…";
  try {
    const res = await fetch(`https://zipcloud.ibsnet.co.jp/api/search?zipcode=${zip}`);
    const json = await res.json();
    const r = json.results && json.results[0];
    if (!r) { status.textContent = "該当する住所が見つかりませんでした。"; return; }
    const addr = `${r.address1}${r.address2}${r.address3}`;
    const field = $("#fAddress");
    const cur = field.value.trim();
    if (!cur) field.value = addr;
    else if (!cur.startsWith(addr)) field.value = addr + cur;
    status.textContent = `住所を入力しました：${addr}（続けて番地・建物名を入力してください）`;
  } catch (e) {
    status.textContent = "検索できませんでした（通信環境をご確認ください）。";
  }
}
$("#zipSearchBtn").addEventListener("click", lookupZip);
$("#fZip").addEventListener("blur", () => {
  if ($("#fZip").value.replace(/[^0-9]/g, "").length === 7 && !$("#fAddress").value.trim()) lookupZip();
});

$("#cardForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const get = (sel) => $(sel).value.trim();
  const name = get("#fName");
  if (!name) { $("#formError").textContent = "お名前を入力してください。"; return; }
  const existing = editingId ? cards.find((x) => x.id === editingId) : null;
  const card = {
    id: existing ? existing.id : uid(),
    createdAt: existing ? existing.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    records: existing ? existing.records || [] : [],
    furigana: get("#fFurigana"), name,
    age: get("#fAge"),
    zip: get("#fZip").replace(/[^0-9]/g, ""),
    address: get("#fAddress"),
    phone: get("#fPhone"), mobile: get("#fMobile"), email: get("#fEmail"),
    introFurigana: get("#fIntroFurigana"), introName: get("#fIntroName"),
    introPlace: get("#fIntroPlace"), introPhone: get("#fIntroPhone"),
    introRelation: get("#fIntroRelation"), introRelationNote: get("#fIntroRelationNote"),
    introNote: get("#fIntroNote"),
    staffOffice: get("#fStaffOffice"), staffName: get("#fStaffName"),
    frontPhoto: pendingFrontPhoto, backPhoto: pendingBackPhoto,
  };
  await persistCard(card);
  currentId = card.id;
  renderList();
  renderDetail(false);
  showView("detailView");
});

/* ---------- 起動 ---------- */
(async () => {
  try {
    await openDb();
    cards = await idbGetAll("cards");
    await initLock();
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    }
  } catch (e) {
    document.body.innerHTML = "<p style='padding:20px'>データベースを開けませんでした。ブラウザの設定をご確認ください。</p>";
  }
})();
