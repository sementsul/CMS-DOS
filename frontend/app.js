// CMS-DOS — фронт: вход, полный экран, DOS-консоль (js-dos) + мост DOS-команд (uploads / passwd).
// Весь код — в IIFE: js-dos.js объявляет глобальные $/ci/... , изолируемся, чтобы не конфликтовать.
(function () {
"use strict";

const byId = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
let ci = null;              // CommandInterface js-dos (после ci-ready)
let booted = false;

// ---------- Аутентификация ----------
async function api(path, opts) {
  const r = await fetch(path, Object.assign({ credentials: "same-origin" }, opts));
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || ("HTTP " + r.status));
  return r.json();
}

function show(overlay) {
  byId("loginOverlay").hidden = overlay !== "login";
  byId("changeOverlay").hidden = overlay !== "change";
}

async function init() {
  const me = await api("/api/me");
  if (!me.authenticated) return show("login");
  if (me.must_change) { byId("oldRow").hidden = true; byId("changeSub").textContent = "Смените пароль по умолчанию"; return show("change"); }
  boot();
}

byId("btnLogin").onclick = async () => {
  byId("loginErr").textContent = "";
  try {
    const res = await api("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: byId("loginUser").value, password: byId("loginPass").value }),
    });
    if (res.must_change) { byId("oldRow").hidden = true; byId("changeSub").textContent = "Смените пароль по умолчанию"; show("change"); }
    else { show(null); boot(); }
  } catch (e) { byId("loginErr").textContent = e.message; }
};

// forceOld: при смене через DOS-команду passwd (уже не первый вход) — нужен текущий пароль
async function submitChange() {
  byId("changeErr").textContent = "";
  const np = byId("newPass").value, np2 = byId("newPass2").value;
  if (np.length < 8) { byId("changeErr").textContent = "Минимум 8 символов"; return false; }
  if (np !== np2) { byId("changeErr").textContent = "Пароли не совпадают"; return false; }
  const body = { new_password: np };
  if (!byId("oldRow").hidden) body.old_password = byId("oldPass").value;
  try {
    await api("/api/passwd", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    byId("newPass").value = byId("newPass2").value = byId("oldPass").value = "";
    return true;
  } catch (e) { byId("changeErr").textContent = e.message; return false; }
}

byId("btnChange").onclick = async () => {
  const ok = await submitChange();
  if (!ok) return;
  show(null);
  if (!booted) boot(); // первый вход → запускаем эмулятор; иначе просто закрываем окно
};

byId("btnLogout").onclick = async () => { try { await api("/api/logout", { method: "POST" }); } catch (e) {} location.reload(); };

// ---------- Полный экран ----------
byId("btnFull").onclick = () => {
  const el = byId("dos");
  if (document.fullscreenElement) document.exitFullscreen();
  else if (el.requestFullscreen) el.requestFullscreen();
};

const lastSig = new Map();   // относительный путь -> подпись содержимого (для детекта изменений)

function sig(bytes) {         // быстрая подпись (длина + djb2-хеш)
  let h = 5381;
  for (let i = 0; i < bytes.length; i++) h = (((h << 5) + h + bytes[i]) >>> 0);
  return bytes.length + ":" + h;
}

// Загрузить файлы СЕРВЕРНОЙ рабочей папки в эмулятор (они станут диском C:).
async function loadServerFiles() {
  const out = [];
  try {
    const tree = await api("/api/tree");
    for (const e of tree) {
      if (e.is_dir) continue;
      const r = await fetch("/api/download?path=" + encodeURIComponent(e.path), { credentials: "same-origin" });
      if (!r.ok) continue;
      const bytes = new Uint8Array(await r.arrayBuffer());
      out.push({ path: e.path, contents: bytes });
      lastSig.set(e.path, sig(bytes));   // считаем загруженное «уже сохранённым» — не гоняем зря
    }
  } catch (e) { /* пусто/ошибка — просто без серверных файлов */ }
  return out;
}

// ---------- Запуск эмулятора ----------
async function boot() {
  if (booted) return; booted = true;

  const serverFiles = await loadServerFiles();   // ← реальные файлы сервера на C:

  // ВАЖНО: js-dos по умолчанию монтирует C: через autoexec `mount c . / c:`.
  // Мы задаём свой конфиг, поэтому монтируем C: сами, иначе диска C нет.
  const dosboxConf = [
    "[cpu]", "core=auto", "cputype=auto", "",
    "[autoexec]",
    "echo off",
    "mount c .",
    "c:",
    "path %PATH%;C:\\CMSDOS",
    "cls",
    "echo.",
    "echo    #####  #     #  #####          #####    ###    #####",
    "echo   #       ##   ##  #             #     #  #   #  #     #",
    "echo   #       # # # #  #####   ###   #     #  #   #  #      ",
    "echo   #       #  #  #       #  ###   #     #  #   #   #####",
    "echo   #       #     #       #        #     #  #   #        #",
    "echo    #####  #     #  #####          #####    ###   #####",
    "echo.",
    "echo    CMS-DOS  -  disk C: = server folder",
    "echo    Commands: dir  type  copy  del  edit   uploads   passwd",
    "echo    Save changes to server: button in top bar",
    "echo.",
    "dir",
  ].join("\n");

  // Утилиты CMS-DOS в PATH (C:\CMSDOS) — команды работают из любой папки.
  // Команды создают файл-маркер в ТЕКУЩЕЙ папке; браузер его ловит опросом ФС.
  const uploadsBat = "@echo off\r\ncd>CMSUPREQ.TMP\r\necho CMS-DOS: vyberite fayl v okne brauzera...\r\n";
  const passwdBat  = "@echo off\r\necho change>CMSPWREQ.TMP\r\necho CMS-DOS: smena parolya v brauzere...\r\n";

  const initFs = [
    { path: "CMSDOS/UPLOADS.BAT", contents: enc.encode(uploadsBat) },
    { path: "CMSDOS/PASSWD.BAT",  contents: enc.encode(passwdBat) },
    ...serverFiles,
  ];

  if (window.emulators) window.emulators.pathPrefix = "/vendor/emulators/";
  // eslint-disable-next-line no-undef
  Dos(byId("dos"), {
    backend: "dosbox",
    pathPrefix: "/vendor/emulators/",
    noCloud: true, kiosk: true, autoStart: true,
    dosboxConf, initFs,
    onEvent: (event, arg) => {
      console.log("[cmsdos] event:", event);
      if (event === "ci-ready") {
        ci = arg; window.__ci = arg;
        status("ФС подключена", "#7fd67f");
        ci.fsTree().then((t) => console.log("[cmsdos] fsTree:", JSON.stringify(t))).catch((e) => console.error("[cmsdos] fsTree err", e));
        startBridge();
      }
    },
  });
}

// ---------- АВТО-синхронизация эмулятор -> сервер (без кнопки) ----------
function isToolPath(p) {   // не сохраняем на сервер утилиты/маркеры CMS-DOS
  const up = p.toUpperCase();
  return up.includes("CMSDOS/") || up.endsWith("CMSUPREQ.TMP") || up.endsWith("CMSPWREQ.TMP");
}
function toRel(fsPath) {   // fs-путь эмулятора -> относительный путь сервера
  return fsPath.replace(/^\/+/, "").replace(/^\.\//, "").replace(/^[A-Za-z]:[\\/]?/, "");
}
function status(text, color) {
  const el = byId("syncStatus");
  el.textContent = text; el.style.color = color || "#7fd67f";
}

let syncing = false;
const handledMarkers = new Set();   // маркеры уже обработаны — не открывать окно повторно
async function autoSync() {
  if (!ci || syncing) return;
  syncing = true;
  try {
    const files = collectFiles(await ci.fsTree(), "", []);
    console.log("[cmsdos] autoSync files:", files.map((f) => f.path), "| lastSig keys:", [...lastSig.keys()]);
    const changed = [];
    const seen = new Set();
    for (const f of files) {
      const rel = toRel(f.path);
      if (!rel || isToolPath(f.path)) continue;
      seen.add(rel);
      let bytes;
      try { bytes = await ci.fsReadFile(f.path); } catch (e) { continue; }
      const s = sig(bytes);
      if (lastSig.get(rel) === s) continue;             // не изменился — пропускаем
      let bin = ""; bytes.forEach((b) => (bin += String.fromCharCode(b)));
      changed.push({ path: rel, content_b64: btoa(bin), _sig: s });
    }
    // удаления: было в lastSig, но в эмуляторе больше нет
    const deleted = [];
    for (const rel of lastSig.keys()) if (!seen.has(rel)) deleted.push(rel);

    if (changed.length || deleted.length) {
      await api("/api/sync", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          files: changed.map(({ path, content_b64 }) => ({ path, content_b64 })),
          deleted: deleted,
        }) });
      changed.forEach((c) => lastSig.set(c.path, c._sig));
      deleted.forEach((rel) => lastSig.delete(rel));
      status("сохранено " + new Date().toLocaleTimeString());
    }
  } catch (e) {
    console.error("[cmsdos] autoSync error", e);
    status("автосейв ошибка: " + e.message, "#ff7a7a");
  } finally {
    syncing = false;
  }
}

// ---------- Мост DOS-команд (по файлам-маркерам) ----------
// Команда создаёт маркер в текущей папке; опрос ФС его находит -> открывает окно ОДИН раз
// (handledMarkers). После загрузки эмулятор перезапускается (location.reload): файл подтянется
// с сервера, маркер исчезнет.
function collectFiles(node, prefix, out) {
  const name = node.name || "";
  const path = prefix === "" ? "/" + name : prefix + "/" + name;
  if (Array.isArray(node.nodes)) node.nodes.forEach((c) => collectFiles(c, node.name ? path : prefix, out));
  else out.push({ path: path, name: name });
  return out;
}
function collectDirs(node, prefix, out) {          // пути каталогов (для записи файла в текущую папку)
  const name = node.name || "";
  const path = prefix === "" ? "/" + name : prefix + "/" + name;
  if (Array.isArray(node.nodes)) {
    if (name) out.push(path);
    node.nodes.forEach((c) => collectDirs(c, node.name ? path : prefix, out));
  }
  return out;
}
function dosDirToRel(dosDir) {                     // "C:\SUB" -> "SUB" ; "C:\" -> ""
  return dosDir.replace(/^[A-Za-z]:\\?/, "").replace(/\\/g, "/").replace(/\/+$/, "").trim();
}

async function startBridge() {
  setInterval(autoSync, 2500);      // авто-сохранение на сервер
  setInterval(pollMarkers, 1000);   // DOS-команды uploads/passwd — по файлам-маркерам
}

async function pollMarkers() {
  if (!ci || syncing) return;
  let files;
  try { files = collectFiles(await ci.fsTree(), "", []); } catch (e) { return; }
  const up = files.find((f) => f.name.toUpperCase() === "CMSUPREQ.TMP" && !handledMarkers.has(f.path));
  const pw = files.find((f) => f.name.toUpperCase() === "CMSPWREQ.TMP" && !handledMarkers.has(f.path));
  if (up) { handledMarkers.add(up.path); handleUpload(up); }         // handled -> окно не повторится
  else if (pw) { handledMarkers.add(pw.path); handlePasswd(pw); }
}

async function handleUpload(marker) {
  let dosDir = "";
  try { dosDir = dec.decode(await ci.fsReadFile(marker.path)).trim(); } catch (e) {}
  const rel = dosDirToRel(dosDir);
  const input = document.createElement("input");
  input.type = "file";
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      const fd = new FormData(); fd.append("file", file); fd.append("dir", rel);
      await fetch("/api/upload", { method: "POST", credentials: "same-origin", body: fd });   // на сервер — надёжно
      status("загружено: " + file.name + " — перезапуск эмулятора...");
      // перезапуск эмулятора: свежий старт подтянет файл с сервера и уберёт маркер
      setTimeout(() => location.reload(), 700);
    } catch (e) {
      status("ошибка загрузки: " + e.message, "#ff7a7a");
    }
  };
  input.click();
}

async function handlePasswd(marker) {
  ci.fsDeleteFile(marker.path).catch(() => {});    // лучший-эффорт; от повтора всё равно защищает handledMarkers
  byId("oldRow").hidden = false;                   // не первый вход -> нужен текущий пароль
  byId("changeSub").textContent = "Смена пароля (команда passwd)";
  show("change");
}

init();
})();
