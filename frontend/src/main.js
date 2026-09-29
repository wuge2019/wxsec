import "./style.css";

const App = () => window.go.main.App;

const state = {
  roots: [],
  packages: [],          // wechat.PackageRef[]
  checked: new Set(),    // appid
  tasks: {},             // id -> Task
  outputs: [],           // 解包产物目录 {appid, dir}
  scanResult: null,      // scanner.Result
  sevFilter: "all",
  textFilter: "",
  browseRoot: "",
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

function status(msg) { $("#statusText").textContent = msg; }

function fmtSize(n) {
  if (!n) return "-";
  if (n > 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
  return (n / 1024).toFixed(0) + " KB";
}
function fmtTime(unix) {
  if (!unix) return "-";
  const d = new Date(unix * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

// ── 标签页切换 ─────────────────────────────────────────────
$("#tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
  document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
  $("#panel-" + btn.dataset.tab).classList.remove("hidden");
  if (btn.dataset.tab === "browser") renderTree(state.browseRoot || $("#browseTarget").value);
  if (btn.dataset.tab === "capture") { refreshCaptureStatus(); loadFlows(); }
});

function showTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
}

// ── 包发现 ─────────────────────────────────────────────────
async function detectRoots() {
  status("正在探测微信缓存目录…");
  try {
    state.roots = (await App().DetectWeChatRoots()) || [];
    const sel = $("#rootSelect");
    sel.replaceChildren();
    let any = false;
    for (const r of state.roots) {
      if (!r.exists) continue;
      any = true;
      const o = el("option", null, `${r.label}　${r.path}`);
      o.value = r.path;
      sel.appendChild(o);
    }
    if (!any) {
      const o = el("option", null, "（未发现微信缓存目录，请手动选择）");
      o.value = "";
      sel.appendChild(o);
      status("未找到微信缓存目录。可手动选择目录或 .wxapkg 文件。");
    } else {
      status(`发现 ${sel.options.length} 个可用缓存目录`);
    }
  } catch (e) {
    status("探测失败: " + e);
  }
}

async function scanRoot() {
  const root = $("#rootSelect").value;
  if (!root) { status("请先选择一个存在的缓存目录"); return; }
  status("枚举小程序包…");
  try {
    state.packages = (await App().ScanPackages(root)) || [];
    state.checked.clear();
    renderPackages();
    status(`共发现 ${state.packages.length} 个小程序包`);
  } catch (e) {
    status("枚举失败: " + e);
    alert("枚举小程序包失败：\n" + e);
  }
}

function renderPackages() {
  const tbody = $("#pkgTable tbody");
  tbody.replaceChildren();
  for (const p of state.packages) {
    const tr = el("tr");
    const tdChk = el("td");
    const chk = el("input");
    chk.type = "checkbox";
    chk.checked = state.checked.has(p.appId);
    chk.addEventListener("change", () => {
      chk.checked ? state.checked.add(p.appId) : state.checked.delete(p.appId);
      syncCheckAll();
    });
    tdChk.appendChild(chk);
    tr.appendChild(tdChk);

    tr.appendChild(el("td", "mono wrap-user", p.appId));
    tr.appendChild(el("td", null, (p.versions || []).join(", ") || "-"));
    tr.appendChild(el("td", null, `${(p.files || []).length} 个文件`));
    tr.appendChild(el("td", null, fmtSize(p.totalSize)));
    tr.appendChild(el("td", null, p.encrypted ? "是(V1MMWX)" : "否"));
    tr.appendChild(el("td", null, fmtTime(p.latestMod)));

    const tdOp = el("td");
    const row = el("div", "row-op");
    const btn = el("button", "btn sm", "解包");
    btn.addEventListener("click", () => unpackOne(p));
    const btnPreview = el("button", "btn ghost sm", "预览");
    btnPreview.addEventListener("click", () => previewPackage(p));
    const btnClean = el("button", "btn danger sm", "清除缓存");
    btnClean.addEventListener("click", () => cleanCache(p));
    row.appendChild(btn);
    row.appendChild(btnPreview);
    row.appendChild(btnClean);
    tdOp.appendChild(row);
    tr.appendChild(tdOp);
    tbody.appendChild(tr);
  }
  syncCheckAll();
}

// 表头全选框：部分勾选时显示为半选状态。
function syncCheckAll() {
  const cb = $("#chkAllPkg");
  if (!cb) return;
  const total = state.packages.length;
  const picked = state.packages.filter((p) => state.checked.has(p.appId)).length;
  cb.checked = total > 0 && picked === total;
  cb.indeterminate = picked > 0 && picked < total;
}

$("#chkAllPkg").addEventListener("change", () => {
  const on = $("#chkAllPkg").checked;
  state.checked = on ? new Set(state.packages.map((p) => p.appId)) : new Set();
  renderPackages();
  status(on ? `已全选 ${state.packages.length} 个小程序包` : "已取消全选");
});

// 批量清除选中 AppID 的微信缓存：一次确认，逐条执行，失败原因可复制。
$("#btnCleanSelected").addEventListener("click", async () => {
  const sel = state.packages.filter((p) => state.checked.has(p.appId));
  if (!sel.length) { status("请先勾选要清除缓存的条目"); return; }
  const root = sel[0].source;
  if (sel.some((p) => p.source !== root)) {
    alert("勾选的条目来自不同的缓存目录，请按目录分批清除。");
    return;
  }
  const bytes = sel.reduce((s, p) => s + (p.totalSize || 0), 0);
  const ids = sel.map((p) => p.appId);
  const preview = ids.slice(0, 8).join("\n") + (ids.length > 8 ? `\n…等共 ${ids.length} 个` : "");
  const tip = `将删除本机微信中 ${ids.length} 个小程序的缓存（约 ${fmtSize(bytes)}，不可撤销，微信下次打开时会自动重新下载）：\n\n` +
    `${preview}\n\n仅删除以上 AppID 的缓存目录，不影响其他小程序与微信其他数据。\n建议先完全退出微信，否则可能有文件被占用。\n\n确认全部删除？`;
  if (!confirm(tip)) { status("已取消批量清除缓存"); return; }
  status(`正在清除 ${ids.length} 个小程序缓存…`);
  try {
    const r = await App().DeletePackageCaches(root, ids);
    const failed = r.failed || [];
    let msg = `已清除 ${r.deleted} 个小程序缓存（${r.files} 个文件 · ${fmtSize(r.bytes)}）`;
    if (failed.length) msg += `\n\n失败 ${failed.length} 个：\n${failed.join("\n")}`;
    status(msg.replace(/\n+/g, " "));
    if (failed.length) alert(msg);
    state.checked.clear();
    await scanRoot();
  } catch (e) {
    status("批量清除缓存失败: " + e);
    alert("批量清除缓存失败：\n" + e);
  }
});

// 清除本机微信小程序缓存：先取目录与规模让用户确认，删除后重新枚举列表。
async function cleanCache(p) {
  let info;
  try {
    info = await App().PackageCacheInfo(p.source, p.appId);
  } catch (e) {
    alert("无法定位缓存目录，已放弃删除：\n" + e);
    return;
  }
  const tip = `将删除本机微信的小程序缓存（不可撤销，微信下次打开该小程序时会重新下载）：\n\n` +
    `AppID：${p.appId}\n目录：${info.path}\n内容：${info.files} 个文件 · ${fmtSize(info.bytes)}\n\n` +
    `仅删除该 AppID 目录，不影响聊天记录等其他微信数据。\n建议先完全退出微信，否则可能有文件被占用。\n\n确认删除？`;
  if (!confirm(tip)) {
    status("已取消删除缓存");
    return;
  }
  try {
    const done = await App().DeletePackageCache(p.source, p.appId);
    status(`已清除 ${done.appId} 缓存：${done.files} 个文件 · ${fmtSize(done.bytes)}`);
    state.checked.delete(p.appId);
    await scanRoot();
  } catch (e) {
    status("清除缓存失败: " + e);
    alert("清除缓存失败：\n" + e);
  }
}

async function previewPackage(p) {
  if (!p.files || !p.files.length) return;
  try {
    const entries = await App().InspectPackage(p.files[0], p.appId);
    const list = (entries || []).slice(0, 300).map((e) => e.name).join("\n");
    alert(`包内文件（前 ${Math.min(entries.length, 300)} / ${entries.length} 项）:\n\n` + list);
  } catch (e) {
    alert("预览失败（加密包请确认 AppID 后重试）：\n" + e);
  }
}

$("#btnDetect").addEventListener("click", detectRoots);
$("#btnScanRoot").addEventListener("click", scanRoot);
$("#btnPickDir").addEventListener("click", async () => {
  const dir = await App().PickDirectory("选择包含 .wxapkg 的目录");
  if (!dir) return;
  const o = el("option", null, `手动目录　${dir}`);
  o.value = dir;
  $("#rootSelect").appendChild(o);
  $("#rootSelect").value = dir;
  scanRoot();
});
$("#btnPickFiles").addEventListener("click", async () => {
  const files = await App().PickWxapkgFiles();
  if (!files || !files.length) return;
  const first = files[0].replace(/\\/g, "/");
  const appidMatch = first.match(/(wx[0-9a-f]{16})/i);
  state.packages = [{
    appId: appidMatch ? appidMatch[1] : "manual",
    files, versions: [], totalSize: 0, latestMod: 0, encrypted: false, source: "手动选择",
  }];
  state.checked = new Set([state.packages[0].appId]);
  renderPackages();
  status(`已加入 ${files.length} 个手工选择的包`);
});

function unpackRequest(source, appId) {
  return {
    source,
    appId: ($("#appidInput").value.trim() || appId || ""),
    outDir: $("#outDir").value.trim(),
    beautify: $("#optBeautify").checked,
    restore: true,
    decompile: $("#optDecompile").checked,
    scan: $("#optAutoScan").checked,
  };
}

// ── 解包任务 ───────────────────────────────────────────────
async function unpackOne(p) {
  if (!p.files || !p.files.length) return;
  const guessed = p.appId.startsWith("wx") ? p.appId : "";
  for (const f of p.files) {
    await startUnpack(unpackRequest(f, guessed));
  }
}

async function startUnpack(req) {
  try {
    const id = await App().Unpack(req);
    state.tasks[id] = { id, kind: "unpack", title: req.source.split(/[\\/]/).pop(), status: "running", progress: 0, message: "排队中" };
    renderTasks();
    showTab("tasks");
  } catch (e) {
    alert("启动解包失败：\n" + e);
  }
}

$("#btnUnpackSelected").addEventListener("click", async () => {
  const sel = state.packages.filter((p) => state.checked.has(p.appId));
  if (!sel.length) { status("请先勾选要解包的条目"); return; }
  for (const p of sel) await unpackOne(p);
});

$("#btnUnpackAll").addEventListener("click", async () => {
  for (const p of state.packages) await unpackOne(p);
});

$("#btnUnpackPick").addEventListener("click", async () => {
  const files = await App().PickWxapkgFiles();
  if (!files || !files.length) return;
  for (const f of files) {
    await startUnpack(unpackRequest(f, ""));
  }
});

$("#btnPickOut").addEventListener("click", async () => {
  const dir = await App().PickDirectory("选择解包输出目录");
  if (dir) $("#outDir").value = dir;
});

function renderTasks() {
  const list = $("#taskList");
  list.replaceChildren();
  const items = Object.values(state.tasks).sort((a, b) => (a.id < b.id ? 1 : -1));
  if (!items.length) {
    list.appendChild(el("div", "empty", "暂无任务。到「包发现」页勾选小程序包后解包。"));
    return;
  }
  for (const t of items) {
    const box = el("div", "task " + (t.status === "error" ? "error" : t.status === "done" ? "done" : ""));
    const row = el("div", "row");
    row.appendChild(el("span", "title", t.title || t.id));
    row.appendChild(el("span", `tag ${t.status === "error" ? "high" : t.status === "done" ? "info" : "low"}`,
      t.status === "running" ? "进行中" : t.status === "done" ? "完成" : "失败"));
    row.appendChild(el("span", "msg", t.error || t.message || ""));
    box.appendChild(row);
    const bar = el("div", "bar");
    const fill = el("i");
    fill.style.width = Math.min(100, t.progress || 0) + "%";
    bar.appendChild(fill);
    box.appendChild(bar);

    if (t.status === "done" && t.output) {
      const ops = el("div", "row");
      ops.style.marginTop = "6px";
      ops.appendChild(el("span", "meta", "输出: " + t.output));
      const b1 = el("button", "btn sm ghost", "打开目录");
      b1.addEventListener("click", () => App().OpenInExplorer(t.output));
      const b2 = el("button", "btn sm ghost", "浏览代码");
      b2.addEventListener("click", () => openBrowse(t.output));
      ops.appendChild(b1);
      ops.appendChild(b2);
      if (t.restored) {
        const b3 = el("button", "btn sm ghost", "查看还原产物");
        b3.addEventListener("click", () => openBrowse(t.restored));
        ops.appendChild(b3);
      }
      box.appendChild(ops);
      registerOutput(t.output);
    }
    list.appendChild(box);
  }
}

function registerOutput(dir) {
  if (!dir) return;
  if (!state.outputs.includes(dir)) state.outputs.push(dir);
  for (const id of ["scanTarget", "browseTarget"]) {
    const sel = $("#" + id);
    if (![...sel.options].some((o) => o.value === dir)) {
      const o = el("option", null, dir.split(/[\\/]/).pop() + "　" + dir);
      o.value = dir;
      sel.appendChild(o);
    }
  }
}

// 后端任务事件推送
if (window.runtime) {
  window.runtime.EventsOn("task", (t) => {
    const old = state.tasks[t.id] || {};
    state.tasks[t.id] = { ...old, ...t };
    renderTasks();
    if (t.kind === "scan" || t.kind === "unpack" || t.kind === "decompile") {
      const kindName = { scan: "扫描", unpack: "解包", decompile: "还原" }[t.kind];
      const pct = t.total > 0 ? Math.round((t.current / t.total) * 100) : Math.round(t.progress || 0);
      $("#progressWrap").classList.remove("hidden");
      $("#progressBar").style.width = Math.min(100, pct) + "%";
      status(`${kindName} ${t.title || ""}: ${t.message || ""} (${pct}%)`);
      if (t.status !== "running") {
        setTimeout(() => $("#progressWrap").classList.add("hidden"), 800);
        if (t.status === "done" && t.kind === "scan") loadScanResult();
        if (t.status === "done" && t.output) { loadScanResult(); loadDecompileInfo(); }
      }
    }
  });

  window.runtime.EventsOn("capture:flow", (f) => {
    cap.flows.push(f);
    if (cap.flows.length > 20000) cap.flows.splice(0, cap.flows.length - 20000);
    if (cap.status) cap.status.flowCount = cap.flows.length;
    scheduleFlowRender();
  });

  window.runtime.EventsOn("capture:log", (line) => {
    const box = $("#capLog");
    if (cap.status) {
      cap.status.logs = [...(cap.status.logs || []), line].slice(-300);
    }
    box.textContent += (box.textContent ? "\n" : "") + line;
    box.scrollTop = box.scrollHeight;
  });

  window.runtime.EventsOn("capture:status", (st) => {
    if (st && st.addr) {
      cap.status = { ...cap.status, ...st };
      renderCapEnv();
    }
  });

  window.runtime.EventsOn("capture:analyze", (rep) => {
    cap.report = rep;
    renderCross();
  });
}

// ── 安全扫描 ───────────────────────────────────────────────
$("#btnScan").addEventListener("click", async () => {
  const dir = $("#scanTarget").value;
  if (!dir) { status("请先解包，或选择解包产物目录"); return; }
  try {
    await App().ScanDir(dir);
    showTab("tasks");
  } catch (e) {
    alert("扫描失败：" + e);
  }
});

async function loadScanResult() {
  try {
    const res = await App().LastScanResult();
    if (!res) return;
    state.scanResult = res;
    renderFindings();
    renderAssets();
    renderSummary();
    showTab("scan");
  } catch (e) { /* 尚无结果 */ }
}

const sevName = { high: "高危", medium: "中危", low: "低危", info: "提示" };

function renderFindings() {
  const tbody = $("#findingTable tbody");
  tbody.replaceChildren();
  const res = state.scanResult;
  $("#scanEmpty").classList.toggle("hidden", !!res);
  $("#findingTable").classList.toggle("hidden", !res);
  if (!res) return;

  $("#scanMeta").textContent =
    `目标 ${res.root} · 扫描 ${res.filesScanned}/${res.filesTotal} 个文件 · 高危 ${res.sevCount.high} 中危 ${res.sevCount.medium} 低危 ${res.sevCount.low} 提示 ${res.sevCount.info} · 耗时 ${(res.durationMs / 1000).toFixed(1)}s`;

  const text = state.textFilter.toLowerCase();
  for (const f of res.findings || []) {
    if (state.sevFilter !== "all" && f.severity !== state.sevFilter) continue;
    if (text && !((f.file + " " + (f.value || "") + " " + (f.title || "")).toLowerCase().includes(text))) continue;

    const tr = el("tr");
    tr.appendChild(el("td", null)).appendChild(el("span", "tag " + f.severity, sevName[f.severity]));
    tr.appendChild(el("td", "mono", f.ruleId));
    tr.appendChild(el("td", null, f.title));

    const tdLoc = el("td", "mono wrap-user");
    const a = el("a", null, `${f.file}:${f.line}`);
    a.href = "javascript:void(0)";
    a.addEventListener("click", () => openAt(f.file, f.line));
    tdLoc.appendChild(a);
    tr.appendChild(tdLoc);

    tr.appendChild(el("td", "mono wrap-user", f.value || ""));
    tr.appendChild(el("td", null, f.recommend || ""));
    tbody.appendChild(tr);
  }
}

$("#sevFilter").addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (!chip) return;
  document.querySelectorAll("#sevFilter .chip").forEach((c) => c.classList.toggle("active", c === chip));
  state.sevFilter = chip.dataset.sev;
  renderFindings();
});
$("#findingSearch").addEventListener("input", (e) => {
  state.textFilter = e.target.value;
  renderFindings();
});

async function openAt(relPath, line) {
  const root = state.scanResult && state.scanResult.root;
  if (!root) return;
  openBrowse(root);
  const abs = root + "\\" + relPath.replace(/\//g, "\\");
  await showFile(abs, line);
}

// ── 接口资产 ───────────────────────────────────────────────
// 资产视图：默认过滤第三方 SDK/公共库自带域名，取消勾选可回溯查看全部。
function assetView() {
  const res = state.scanResult;
  if (!res) return { assets: [], hosts: [], filtered: 0, vendors: [] };
  const sdkAssets = res.sdkAssets || [];
  if (!$("#chkFilterSDK").checked) {
    return {
      assets: [...(res.assets || []), ...sdkAssets],
      hosts: [...(res.hosts || []), ...(res.sdkHosts || [])],
      filtered: 0,
      vendors: [],
    };
  }
  const vendors = [...new Set(sdkAssets.map((a) => a.sdk))].sort();
  return { assets: res.assets || [], hosts: res.hosts || [], filtered: sdkAssets.length, vendors };
}

function renderAssets() {
  const res = state.scanResult;
  const view = assetView();
  const hostsBox = $("#hostChips");
  const tbody = $("#assetTable tbody");
  hostsBox.replaceChildren();
  tbody.replaceChildren();
  $("#assetEmpty").classList.toggle("hidden", !!res && view.assets.length > 0);
  $("#assetTable").classList.toggle("hidden", !res);
  if (!res) {
    $("#assetNote").textContent = "";
    return;
  }

  for (const h of view.hosts) hostsBox.appendChild(el("span", "chip", h));
  $("#assetNote").textContent = view.filtered
    ? `已过滤 ${view.filtered} 条第三方 SDK 自带域名（${view.vendors.join("、")}），取消勾选可查看全部。`
    : "";

  for (const a of view.assets) {
    const tr = el("tr");
    tr.appendChild(el("td", "mono wrap-user", a.url));
    tr.appendChild(el("td", null, a.scheme));
    tr.appendChild(el("td", "mono wrap-user", a.path || "/"));
    tr.appendChild(el("td", "mono wrap-user", a.file + (a.line ? ":" + a.line : "")));
    tr.appendChild(el("td", null, String(a.count)));
    tr.appendChild(el("td", null, a.sdk || "目标"));
    const tdOp = el("td");
    const btn = el("button", "btn sm ghost", "复制");
    btn.addEventListener("click", () => { App().ClipboardWrite(a.url); status("已复制 " + a.url); });
    tdOp.appendChild(btn);
    tr.appendChild(tdOp);
    tbody.appendChild(tr);
  }
}

$("#chkFilterSDK").addEventListener("change", () => renderAssets());

$("#btnCopyHosts").addEventListener("click", () => {
  const hosts = assetView().hosts;
  if (!hosts.length) return;
  App().ClipboardWrite(hosts.join("\n"));
  status(`已复制 ${hosts.length} 个域名`);
});

// ── 报告导出 ───────────────────────────────────────────────
async function exportReport(fmt) {
  const box = $("#reportResult");
  try {
    const path = await App().ExportReport(fmt, $("#reportDir").value.trim());
    box.classList.remove("hidden");
    box.textContent = "";
    box.appendChild(el("div", null, `已导出: ${path}`));
    const btn = el("button", "btn sm ghost", "打开报告");
    btn.style.marginTop = "6px";
    btn.addEventListener("click", () => App().OpenInExplorer(path));
    box.appendChild(btn);
    status("报告已导出");
  } catch (e) {
    alert("导出失败：\n" + e);
  }
}
$("#btnExportHtml").addEventListener("click", () => exportReport("html"));
$("#btnExportJson").addEventListener("click", () => exportReport("json"));
$("#btnPickReportDir").addEventListener("click", async () => {
  const dir = await App().PickDirectory("选择报告输出目录");
  if (dir) $("#reportDir").value = dir;
});

function renderSummary() {
  const res = state.scanResult;
  const box = $("#reportSummary");
  box.replaceChildren();
  if (!res) { box.appendChild(el("div", "meta", "暂无扫描数据")); return; }
  const kv = [
    ["扫描目标", res.root],
    ["小程序包数量", String(res.filesTotal)],
    ["实际扫描", String(res.filesScanned)],
    ["高危", String(res.sevCount.high)],
    ["中危", String(res.sevCount.medium)],
    ["低危", String(res.sevCount.low)],
    ["提示", String(res.sevCount.info)],
    ["关联域名", String((res.hosts || []).length)],
    ["接口 URL", String((res.assets || []).length)],
    ["第三方 SDK URL", String((res.sdkAssets || []).length)],
    ["扫描耗时", (res.durationMs / 1000).toFixed(1) + " 秒"],
  ];
  for (const [k, v] of kv) {
    box.appendChild(el("div", null, k + "：")).appendChild(el("b", null, v));
  }
}

// ── 代码浏览 ───────────────────────────────────────────────
function openBrowse(dir) {
  const sel = $("#browseTarget");
  if (![...sel.options].some((o) => o.value === dir)) {
    const o = el("option", null, dir.split(/[\\/]/).pop() + "　" + dir);
    o.value = dir;
    sel.appendChild(o);
  }
  sel.value = dir;
  // 先记下目标目录再切标签：标签处理器会按 browseRoot 渲染，避免渲染两次。
  state.browseRoot = dir;
  showTab("browser");
}

$("#browseTarget").addEventListener("change", (e) => renderTree(e.target.value));
$("#scanTarget").addEventListener("change", () => {});

$("#btnDecompileHere").addEventListener("click", async () => {
  const dir = $("#browseTarget").value;
  if (!dir) { status("请先选择要还原的解包目录"); return; }
  try {
    await App().DecompileDir(dir);
    showTab("tasks");
  } catch (e) {
    alert("还原失败：" + e);
  }
});

// 还原汇总信息（产物数量与跳过原因）显示在代码浏览面板。
async function loadDecompileInfo() {
  const box = $("#decompileInfo");
  try {
    const res = await App().LastDecompile();
    if (!res) { box.textContent = ""; return; }
    let wxml = 0, wxss = 0;
    for (const p of res.pages || []) (p.kind === "wxml" ? wxml++ : wxss++);
    box.textContent = `已还原 WXML ${wxml} 个 · WXSS ${wxss} 个 · 编译产物 ${res.bundles.length} 个 · 跳过 ${(res.skipped || []).length} 个`;
    box.title = (res.notes || []).concat(res.skipped || []).join("\n");
  } catch (e) {
    box.textContent = "";
  }
}

async function renderTree(root) {
  state.browseRoot = root;
  const tree = $("#fileTree");
  tree.replaceChildren();
  if (!root) {
    tree.appendChild(el("div", "meta", "暂无解包产物。请先完成解包任务。"));
    return;
  }
  let entries;
  try {
    entries = await App().ListDir(root);
  } catch (e) {
    tree.appendChild(el("div", "meta", "读取失败: " + e));
    return;
  }
  for (const en of entries) {
    const holder = el("div", null);
    node(holder, en, 0);
    tree.appendChild(holder);
  }
}

function node(holder, entry, depth) {
  const row = el("div", "node");
  row.style.paddingLeft = 4 + depth * 14 + "px";
  const tw = el("span", "tw", entry.isDir ? "▸" : "·");
  row.appendChild(tw);
  row.appendChild(el("span", null, entry.name));
  holder.appendChild(row);

  if (!entry.isDir) {
    row.addEventListener("click", () => {
      document.querySelectorAll(".file-tree .node.active").forEach((n) => n.classList.remove("active"));
      row.classList.add("active");
      showFile(entry.path);
    });
    return;
  }

  let kids = null;
  row.addEventListener("click", async () => {
    const open = holder.querySelector(":scope > .kids");
    if (open) { open.remove(); tw.textContent = "▸"; return; }
    tw.textContent = "▾";
    kids = el("div", "kids");
    holder.appendChild(kids);
    try {
      const list = await App().ListDir(entry.path);
      for (const en of (list || [])) node(kids, en, depth + 1);
      if (!list || !list.length) kids.appendChild(el("div", "meta", "（空目录）"));
    } catch (e) {
      kids.appendChild(el("div", "meta", "读取失败"));
    }
  });
}

async function showFile(absPath, highlightLine) {
  const view = $("#codeView");
  view.replaceChildren();
  $("#codePath").textContent = absPath;
  let src;
  try {
    src = await App().ReadSource(state.browseRoot || absPath, absPath);
  } catch (e) {
    $("#codeInfo").textContent = "";
    view.textContent = "无法打开: " + e;
    return;
  }
  $("#codeInfo").textContent = `${src.lines} 行 · ${fmtSize(src.size)}`;
  const lines = (src.content || "").split("\n");
  const frag = document.createDocumentFragment();
  lines.forEach((ln, i) => {
    const row = el("div", "cl" + (i + 1 === highlightLine ? " hl" : ""));
    row.appendChild(el("span", "ln", String(i + 1)));
    row.appendChild(el("span", "tx", ln));
    frag.appendChild(row);
  });
  view.appendChild(frag);
  if (highlightLine) {
    const target = view.querySelector(".cl.hl");
    if (target) target.scrollIntoView({ block: "center" });
  }
}

// ── 抓包分析 ───────────────────────────────────────────────
const cap = {
  status: null,
  flows: [],
  report: null,
  filter: "all",     // 记录筛选：all / decrypted / connect / plain
  xfilter: "all",    // 对照分类
  text: "",
  renderTimer: null,
};

const catName = { both: "两者都有", dynamic: "仅动态", static: "仅包内", "host-only": "仅域名" };

function flowURL(f) {
  if (f.url) return f.url;
  if (f.scheme === "connect") return `https://${f.host}/（未解密，仅域名）`;
  return f.host;
}

function fmtClock(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return "-";
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function captureOptions() {
  return {
    port: Number($("#capPort").value) || 0,
    intercept: $("#capIntercept").checked,
    sysProxy: $("#capSysProxy").checked,
  };
}

async function refreshCaptureStatus() {
  try {
    cap.status = await App().CaptureStatus();
    renderCapEnv();
  } catch (e) {
    status("读取抓包状态失败：" + e);
  }
}

function renderCapEnv() {
  const st = cap.status;
  if (!st) return;
  const grid = $("#capEnv");
  const items = [
    ["代理监听", st.running ? `运行中　${st.addr}` : `未启动（${st.addr}）`],
    ["解密模式", st.intercept ? "解密 HTTPS" : "仅记录域名"],
    ["根证书", st.caInstalled ? `已装入当前用户信任存储（${st.caExpires} 到期）` : "未安装 —— 点「安装本地根证书」"],
    ["系统代理", sysProxyText(st.sysProxy)],
    ["记录条数", `${st.flowCount} 条${st.dropped ? `（容量上限丢弃 ${st.dropped} 条）` : ""}`],
    ["静态对照", st.scanReady ? `${st.crossRows ? st.crossRows + " 条对照记录　" : "已有扫描结果，可执行交叉分析　"}${st.scanRoot || ""}` : "尚未扫描，先完成第 3 步"],
    ["记录文件", st.storePath || "-"],
  ];
  grid.replaceChildren(...items.map(([k, v]) => {
    const cell = el("div");
    cell.appendChild(el("span", "meta", k + "："));
    cell.appendChild(el("b", "mono", v));
    return cell;
  }));

  $("#btnCapStart").disabled = !!st.running;
  $("#btnCapStop").disabled = !st.running;
  $("#btnSysEnable").disabled = !st.running;
  $("#btnSysRestore").disabled = !(st.sysProxy && st.sysProxy.managed);
  $("#capLog").textContent = (st.logs || []).slice(-40).join("\n");
  $("#capLog").scrollTop = $("#capLog").scrollHeight;
  $("#capMeta").textContent = `共 ${st.flowCount} 条记录`;
}

function sysProxyText(sp) {
  if (!sp) return "读取失败";
  if (sp.managed) {
    const origin = sp.backup ? (sp.backup.enable ? sp.backup.server : "未启用") : "未知";
    return `已被本工具接管 → ${sp.managedAddr}（原始：${origin}，备份于 ${sp.backupAt || "-"}）`;
  }
  return sp.enabled ? `用户自定义：${sp.server || "-"}` : "未启用";
}

function renderFlows() {
  const tbody = $("#flowTable tbody");
  tbody.replaceChildren();
  const kw = cap.text.trim().toLowerCase();
  let shown = 0;
  for (const f of [...cap.flows].reverse()) {
    if (cap.filter === "decrypted" && !f.intercepted) continue;
    if (cap.filter === "connect" && f.intercepted) continue;
    if (cap.filter === "plain" && f.scheme !== "http") continue;
    if (kw && !(`${flowURL(f)} ${f.appId || ""} ${f.contentType || ""}`.toLowerCase().includes(kw))) continue;
    const tr = el("tr");
    tr.appendChild(el("td", "mono", fmtClock(f.time)));
    tr.appendChild(el("td", "mono", f.method || "-"));
    const tdURL = el("td", "mono wrap-user");
    tdURL.textContent = flowURL(f);
    tr.appendChild(tdURL);
    tr.appendChild(el("td", null, f.status ? String(f.status) : "-"));
    tr.appendChild(el("td", "mono", f.appId || "-"));
    tr.appendChild(el("td", null, f.wxVersion || "-"));
    tr.appendChild(el("td", null, f.respBytes ? fmtSize(f.respBytes) : "-"));
    tr.appendChild(el("td", null, f.durationMs ? f.durationMs + " ms" : "-"));
    const note = f.note || (f.intercepted ? "" : "仅域名");
    tr.appendChild(el("td", "meta", note));
    tbody.appendChild(tr);
    if (++shown >= 1000) break;
  }
  $("#flowEmpty").classList.toggle("hidden", shown > 0);
  if (cap.status) $("#capMeta").textContent = `共 ${cap.status.flowCount} 条，当前显示 ${shown} 条`;
}

function renderCross() {
  const tbody = $("#crossTable tbody");
  tbody.replaceChildren();
  const rep = cap.report;
  if (!rep || !rep.rows) {
    $("#crossEmpty").classList.remove("hidden");
    return;
  }
  $("#crossEmpty").classList.toggle("hidden", rep.rows.length > 0);
  for (const [k, v] of [["both", rep.stats.both], ["dynamic", rep.stats.dynamicOnly], ["static", rep.stats.staticOnly], ["host-only", rep.stats.hostOnly]]) {
    const chip = document.querySelector(`#crossFilter .chip[data-xcat="${k}"]`);
    if (chip) chip.textContent = `${catName[k]} ${v || 0}`;
  }
  for (const r of rep.rows) {
    if (cap.xfilter !== "all" && r.category !== cap.xfilter) continue;
    const tr = el("tr");
    const tdCat = el("td");
    tdCat.appendChild(el("span", "tag " + ({ both: "info", dynamic: "medium", static: "low", "host-only": "high" }[r.category] || "info"), catName[r.category] || r.category));
    tr.appendChild(tdCat);
    tr.appendChild(el("td", "mono", r.host));
    tr.appendChild(el("td", "mono wrap-user", r.path + (r.pattern ? "　(模板匹配)" : "")));
    tr.appendChild(el("td", "mono", (r.methods || []).join(", ") || "-"));
    tr.appendChild(el("td", null, (r.statuses || []).join(", ") || "-"));
    tr.appendChild(el("td", null, String(r.dynamicCount || 0)));
    tr.appendChild(el("td", null, String(r.staticCount || 0)));
    tr.appendChild(el("td", "meta wrap-user", (r.staticFiles || []).join("; ") || (r.sdk ? "第三方 SDK：" + r.sdk : "-")));
    tr.appendChild(el("td", "meta", (r.notes || []).join("；")));
    tbody.appendChild(tr);
  }
}

async function loadFlows() {
  try {
    cap.flows = (await App().ListFlows(0)) || [];
    if (cap.status) cap.status.flowCount = cap.flows.length;
    renderFlows();
  } catch (e) {
    status("读取抓包记录失败：" + e);
  }
}

function scheduleFlowRender() {
  if (cap.renderTimer) return;
  cap.renderTimer = setTimeout(() => {
    cap.renderTimer = null;
    renderFlows();
  }, 300);
}

$("#btnCapStart").addEventListener("click", async () => {
  const opt = captureOptions();
  if (opt.intercept && cap.status && !cap.status.caInstalled) {
    if (!confirm("尚未安装本地根证书，HTTPS 请求只会记录到域名级别。\n\n点「确定」继续启动（启动后可再安装），点「取消」先去安装根证书。")) return;
  }
  if (opt.sysProxy && !confirm("接管系统代理后，本机的 HTTPS 流量都会经过 wxsec 本地代理。\n测试结束请务必点击「恢复系统代理」或关闭本工具。\n\n确认接管？")) return;
  status("正在启动抓包代理…");
  try {
    cap.status = await App().StartCapture(opt);
    renderCapEnv();
    await loadFlows();
    status(`抓包代理已启动：${cap.status.addr}，请在微信中操作目标小程序`);
  } catch (e) {
    alert("启动抓包失败：\n" + e + "\n\n常见原因：端口被占用（换一个端口），或端口小于 1024。");
    status("抓包启动失败");
    await refreshCaptureStatus();
  }
});

$("#btnCapStop").addEventListener("click", async () => {
  try {
    cap.status = await App().StopCapture();
    renderCapEnv();
    await loadFlows();
    status("抓包已停止，记录仍保留在本机");
  } catch (e) {
    alert("停止抓包失败：" + e);
  }
});

$("#btnCAPaste").addEventListener("click", async () => {
  const addr = (cap.status && cap.status.addr) || `127.0.0.1:${Number($("#capPort").value) || 18888}`;
  try {
    await App().ClipboardWrite(addr);
    status("代理地址已复制：" + addr + "（手机在同一 Wi-Fi 时手动填写 Wi-Fi 代理）");
  } catch (e) {
    status("复制失败：" + e);
  }
});

$("#btnCAInstall").addEventListener("click", async () => {
  if (!confirm("将把 wxsec 本地根证书装入「当前用户的受信任根证书颁发机构」。\n\n这只影响当前 Windows 用户，不影响系统级信任；测试结束后建议点「移除根证书」。\n确认继续？")) return;
  status("正在安装根证书…");
  try {
    const info = await App().InstallCA();
    await refreshCaptureStatus();
    status(info.installed ? `根证书已安装：${info.path}` : "安装命令已执行，但系统仍未信任该证书");
  } catch (e) {
    alert("根证书安装失败：\n" + e + "\n\n可以改为手动安装：「导出根证书」后，双击证书 → 安装证书 → 本地计算机/当前用户 → 受信任的根证书颁发机构。");
    status("根证书安装失败");
  }
});

$("#btnCAUninstall").addEventListener("click", async () => {
  if (!confirm("从当前用户的受信任根存储中移除 wxsec 根证书？")) return;
  try {
    await App().UninstallCA();
    await refreshCaptureStatus();
    status("根证书已移除");
  } catch (e) {
    alert("移除失败：" + e);
  }
});

$("#btnCAExport").addEventListener("click", async () => {
  const dir = await App().PickDirectory("选择根证书导出位置");
  if (!dir) return;
  try {
    const path = await App().ExportCA(dir);
    status("根证书已导出：" + path + "（手机安装该证书并信任后即可抓到 HTTPS 明文）");
    try { await App().OpenInExplorer(path); } catch (e) { /* 忽略 */ }
  } catch (e) {
    alert("导出失败：" + e);
  }
});

$("#btnSysEnable").addEventListener("click", async () => {
  if (!confirm("接管系统代理后，本机 HTTPS 流量都会经过 wxsec。测试结束请点「恢复系统代理」。\n确认继续？")) return;
  try {
    const st = await App().SysProxyEnable();
    await refreshCaptureStatus();
    status("已接管系统代理 → " + (st.managedAddr || ""));
  } catch (e) {
    alert("接管失败：" + e);
  }
});

$("#btnSysRestore").addEventListener("click", async () => {
  try {
    const st = await App().SysProxyRestore();
    await refreshCaptureStatus();
    status("系统代理已恢复：" + (st.enabled ? st.server : "未启用"));
  } catch (e) {
    alert("恢复系统代理失败：" + e + "\n\n请手动检查「设置 → 网络和 Internet → 代理」。");
  }
});

$("#btnFlowRefresh").addEventListener("click", loadFlows);

$("#btnFlowClear").addEventListener("click", async () => {
  if (!confirm("清空全部抓包记录（内存与本机 flows.jsonl）？此操作不可撤销。")) return;
  try {
    await App().ClearFlows();
    cap.flows = [];
    cap.report = null;
    renderFlows();
    renderCross();
    await refreshCaptureStatus();
    status("抓包记录已清空");
  } catch (e) {
    alert("清空失败：" + e);
  }
});

$("#btnAnalyze").addEventListener("click", async () => {
  status("正在交叉分析…");
  try {
    cap.report = await App().AnalyzeCapture();
    renderCross();
    await refreshCaptureStatus();
    status(`交叉分析完成：${cap.report.rows.length} 条对照记录`);
  } catch (e) {
    alert("交叉分析失败：\n" + e + "\n\n需要先完成一次安全扫描（第 3 步），并且已有静态接口资产。");
    status("交叉分析失败");
  }
});

$("#btnExportXlsx").addEventListener("click", async () => {
  const dir = await App().PickDirectory("选择 URL 清单导出位置") || "";
  status("正在导出 Excel…");
  try {
    const path = await App().ExportCaptureExcel(dir);
    status("URL 清单已导出：" + path);
    if (confirm("导出完成：\n" + path + "\n\n是否在资源管理器中打开？")) {
      await App().OpenInExplorer(path);
    }
  } catch (e) {
    alert("导出失败：" + e);
    status("导出失败");
  }
});

$("#flowSearch").addEventListener("input", (e) => { cap.text = e.target.value; renderFlows(); });

$("#capCatFilter").addEventListener("click", (e) => {
  const btn = e.target.closest(".chip");
  if (!btn) return;
  cap.filter = btn.dataset.cat;
  document.querySelectorAll("#capCatFilter .chip").forEach((c) => c.classList.toggle("active", c === btn));
  renderFlows();
});

$("#crossFilter").addEventListener("click", (e) => {
  const btn = e.target.closest(".chip");
  if (!btn) return;
  cap.xfilter = btn.dataset.xcat;
  document.querySelectorAll("#crossFilter .chip").forEach((c) => c.classList.toggle("active", c === btn));
  renderCross();
});

// ── 初始化 ─────────────────────────────────────────────────
(async function init() {
  try {
    $("#versionLabel").textContent = "wxsec v" + (await App().VersionInfo());
    $("#legalNotice").textContent = await App().LegalNotice();
  } catch (e) { /* 非 wails 环境预览 */ }
  await detectRoots();
  renderTasks();
  loadDecompileInfo();
  refreshCaptureStatus();
  $("#taskList").appendChild(el("div", "hint", "免责声明：本工具仅用于获得授权的小程序安全测试与学习研究。"));
})();
