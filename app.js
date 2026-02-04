/* Password Forge - static password generator (no network, no storage) */

/**
 * We intentionally avoid any logging of password content.
 * Randomness must use Web Crypto (crypto.getRandomValues).
 */

const CHARSETS = {
  letters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/~",
};

function qs(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el;
}

function clampInt(v, min, max) {
  const n = Number.parseInt(String(v), 10);
  if (Number.isNaN(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function uniqueChars(str) {
  return Array.from(new Set(Array.from(str)));
}

function buildCategoryChars({ enabled, excludeSet }) {
  /** @type {{key: string, label: string, chars: string[] }[]} */
  const categories = [];

  const add = (key, label, raw) => {
    if (!enabled[key]) return;
    let chars = Array.from(raw);
    if (excludeSet.size) chars = chars.filter((c) => !excludeSet.has(c));
    chars = uniqueChars(chars).sort(); // stable (not security relevant)
    categories.push({ key, label, chars });
  };

  add("letters", "字母", CHARSETS.letters);
  add("digits", "数字", CHARSETS.digits);
  add("symbols", "符号", CHARSETS.symbols);

  return categories;
}

function concatAllChars(categories) {
  const all = [];
  for (const cat of categories) all.push(...cat.chars);
  return uniqueChars(all);
}

function cryptoRandomUint32() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0];
}

function cryptoRandomInt(maxExclusive) {
  // Rejection sampling to avoid modulo bias.
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error("maxExclusive must be positive integer");
  }
  const maxUint = 0xffffffff;
  const limit = Math.floor((maxUint + 1) / maxExclusive) * maxExclusive;
  while (true) {
    const x = cryptoRandomUint32();
    if (x < limit) return x % maxExclusive;
  }
}

function pick(charsArray) {
  return charsArray[cryptoRandomInt(charsArray.length)];
}

function shuffleInPlace(arr) {
  // Fisher–Yates using crypto RNG
  for (let i = arr.length - 1; i > 0; i--) {
    const j = cryptoRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function estimateEntropyBits(length, charsetSize) {
  if (length <= 0 || charsetSize <= 1) return 0;
  return length * Math.log2(charsetSize);
}

function strengthFromEntropy(bits) {
  // Practical, explainable thresholds (rough)
  if (bits < 35) return { level: "弱", cls: "weak" };
  if (bits < 55) return { level: "中", cls: "medium" };
  if (bits < 80) return { level: "强", cls: "strong" };
  return { level: "极强", cls: "verystrong" };
}

function formatBits(bits) {
  if (!Number.isFinite(bits)) return "0";
  if (bits >= 100) return bits.toFixed(0);
  return bits.toFixed(1);
}

function validateConfig({ length, categories, allChars }) {
  if (!categories.length) {
    return { ok: false, message: "请至少选择一个字符集（字母/数字/符号）。" };
  }
  if (!allChars.length) {
    return {
      ok: false,
      message: "当前设置导致可用字符集为空（可能排除字符过多）。请调整排除列表或字符集选择。",
    };
  }
  if (length < 8 || length > 128) {
    return { ok: false, message: "长度范围为 8–128。" };
  }
  return { ok: true, message: "" };
}

function generateOne({ length, allChars }) {
  /** @type {string[]} */
  const out = [];

  while (out.length < length) out.push(pick(allChars));
  shuffleInPlace(out);
  return out.join("");
}

async function writeClipboard(text) {
  // Prefer async clipboard API; fallback to execCommand for older browsers.
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    await navigator.clipboard.writeText(text);
    return;
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "true");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  ta.style.top = "0";
  document.body.appendChild(ta);
  ta.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(ta);
  if (!ok) throw new Error("copy failed");
}

function createToast() {
  const toastEl = qs("toast");
  let timer = null;

  const show = (msg) => {
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(() => toastEl.classList.remove("show"), 1800);
  };
  return { show };
}

function setAlert(message) {
  const alertEl = qs("alert");
  if (!message) {
    alertEl.hidden = true;
    alertEl.textContent = "";
    return;
  }
  alertEl.hidden = false;
  alertEl.textContent = message;
}

function maskPassword(pw) {
  // Keep length information; hide content.
  return "•".repeat(Math.min(24, Math.max(8, pw.length)));
}

function renderResults({
  passwords,
  showPlain,
  strength,
  strengthDetail,
  perItemMeta,
}) {
  const list = qs("resultsList");
  const meta = qs("resultsMeta");
  const badge = qs("strengthBadge");
  const detail = qs("strengthDetail");

  list.innerHTML = "";
  if (!passwords.length) {
    meta.textContent = "暂无结果";
    badge.className = "badge";
    badge.textContent = "—";
    detail.textContent = "等待生成";
    return;
  }

  meta.textContent = `已生成 ${passwords.length} 条`;
  badge.className = `badge ${strength.cls}`;
  badge.textContent = strength.level;
  detail.textContent = strengthDetail;

  passwords.forEach((pw, idx) => {
    const li = document.createElement("li");
    li.className = "item";

    const left = document.createElement("div");
    left.className = "pw";

    const value = document.createElement("div");
    value.className = "pw-value";
    value.textContent = showPlain ? pw : maskPassword(pw);
    value.title = showPlain ? pw : "已隐藏（可开启显示明文）";

    const metaEl = document.createElement("div");
    metaEl.className = "pw-meta";
    metaEl.textContent = perItemMeta[idx] ?? "";

    left.appendChild(value);
    left.appendChild(metaEl);

    const right = document.createElement("div");
    right.className = "item-actions";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-small";
    copyBtn.textContent = "复制";
    copyBtn.dataset.index = String(idx);
    copyBtn.setAttribute("aria-label", `复制第 ${idx + 1} 条密码`);

    right.appendChild(copyBtn);

    li.appendChild(left);
    li.appendChild(right);
    list.appendChild(li);
  });
}

function readConfig() {
  const length = clampInt(qs("lengthNumber").value, 8, 128);

  const enabled = {
    letters: qs("setLetters").checked,
    digits: qs("setDigits").checked,
    symbols: qs("setSymbols").checked,
  };

  const excludeSet = new Set();

  const categories = buildCategoryChars({ enabled, excludeSet });
  const allChars = concatAllChars(categories);

  return { length, enabled, categories, allChars };
}

function syncLengthUI(nextLength) {
  const n = clampInt(nextLength, 8, 128);
  const slider = qs("length");
  const number = qs("lengthNumber");
  slider.value = String(n);
  number.value = String(n);
}

function main() {
  const toast = createToast();

  const btnGenerate = qs("btnGenerate");
  const btnClear = qs("btnClear");
  const showPasswords = qs("showPasswords");
  const list = qs("resultsList");

  let state = {
    passwords: /** @type {string[]} */ ([]),
    perItemMeta: /** @type {string[]} */ ([]),
    strength: { level: "—", cls: "" },
    strengthDetail: "等待生成",
  };

  const rerender = () => {
    renderResults({
      passwords: state.passwords,
      showPlain: showPasswords.checked,
      strength: state.strength,
      strengthDetail: state.strengthDetail,
      perItemMeta: state.perItemMeta,
    });
  };

  const doGenerate = () => {
    setAlert("");

    const cfg = readConfig();
    syncLengthUI(cfg.length);

    const v = validateConfig({
      length: cfg.length,
      categories: cfg.categories,
      allChars: cfg.allChars,
    });
    if (!v.ok) {
      state.passwords = [];
      state.perItemMeta = [];
      state.strength = { level: "—", cls: "" };
      state.strengthDetail = "等待生成";
      setAlert(v.message);
      rerender();
      return;
    }

    const passwords = [
      generateOne({
        length: cfg.length,
        allChars: cfg.allChars,
      }),
    ];

    const bits = estimateEntropyBits(cfg.length, cfg.allChars.length);
    const strength = strengthFromEntropy(bits);
    const detail = `长度 ${cfg.length}，字符集 ${cfg.allChars.length}，估算熵 ${formatBits(bits)} bits`;

    const perItemMeta = passwords.map(() => {
      const cats = cfg.categories.map((c) => c.label).join(" / ");
      return `类别：${cats || "—"}；${detail}`;
    });

    state.passwords = passwords;
    state.perItemMeta = perItemMeta;
    state.strength = strength;
    state.strengthDetail = detail;
    rerender();
    toast.show("已生成");
  };

  btnGenerate.addEventListener("click", doGenerate);

  btnClear.addEventListener("click", () => {
    setAlert("");
    state.passwords = [];
    state.perItemMeta = [];
    state.strength = { level: "—", cls: "" };
    state.strengthDetail = "等待生成";
    rerender();
    toast.show("已清空");
  });

  qs("length").addEventListener("input", (e) => {
    syncLengthUI(e.target.value);
  });
  qs("lengthNumber").addEventListener("input", (e) => {
    syncLengthUI(e.target.value);
  });

  showPasswords.addEventListener("change", () => rerender());

  list.addEventListener("click", async (e) => {
    const target = /** @type {HTMLElement} */ (e.target);
    const btn = target?.closest?.("button[data-index]");
    if (!btn) return;
    const idx = clampInt(btn.dataset.index, 0, state.passwords.length - 1);
    const pw = state.passwords[idx];
    if (!pw) return;
    try {
      await writeClipboard(pw);
      toast.show(`已复制第 ${idx + 1} 条`);
    } catch {
      toast.show("复制失败（可能被浏览器拦截）");
    }
  });

  // Convenience: Ctrl/Cmd + Enter to generate (when focus in inputs)
  document.addEventListener("keydown", (e) => {
    const isMac = navigator.platform.toLowerCase().includes("mac");
    const accel = isMac ? e.metaKey : e.ctrlKey;
    if (accel && e.key === "Enter") doGenerate();
  });

  // Initial render
  syncLengthUI(qs("lengthNumber").value);
  rerender();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", main);
} else {
  main();
}

