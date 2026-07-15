const EXPECTED_MODULES = Object.freeze({
  app: "app.enc",
  quote: "quote.enc",
  inventory: "inventory.enc",
  pom: "pom.enc",
  mechatronics: "mechatronics.enc"
});

const MODULE_TOKENS = Object.freeze({
  quote: "__SECURE_MODULE_QUOTE__",
  inventory: "__SECURE_MODULE_INVENTORY__",
  pom: "__SECURE_MODULE_POM__",
  mechatronics: "__SECURE_MODULE_MECHATRONICS__"
});

const LOADER_FILES = Object.freeze({
  quote: "module-quote.html",
  inventory: "module-inventory.html",
  pom: "module-pom.html",
  mechatronics: "module-mechatronics.html"
});

const MODE_QUERIES = Object.freeze({
  inventory: "?standalone=1",
  pom: "?embed=1",
  mechatronics: "?embed=1"
});

const LOGIN_TITLE = "安全访问 | 备件运营管理平台";
const PLATFORM_TITLE = "备件运营管理平台";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function fromBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error("加密清单格式不正确");
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
  return output;
}

function validateManifest(manifest) {
  if (!manifest || manifest.version !== 1 || manifest.entry !== "app" || manifest.encoding !== "utf-8") throw new Error("站点版本不兼容");
  if (manifest.kdf?.name !== "PBKDF2" || manifest.kdf?.hash !== "SHA-256" || !Number.isInteger(manifest.kdf?.iterations) || manifest.kdf.iterations < 100000) throw new Error("密钥参数不正确");
  if (manifest.cipher?.name !== "AES-GCM" || manifest.cipher?.keyLength !== 256 || manifest.cipher?.tagLength !== 128) throw new Error("加密参数不正确");
  const salt = fromBase64(manifest.kdf.salt);
  if (salt.byteLength < 16) throw new Error("密钥参数不正确");
  if (!Array.isArray(manifest.modules) || manifest.modules.length !== 5) throw new Error("模块清单不完整");
  const modules = new Map();
  for (const module of manifest.modules) {
    if (!module || EXPECTED_MODULES[module.id] !== module.file || modules.has(module.id)) throw new Error("模块清单不正确");
    if (!Number.isInteger(module.bytes) || module.bytes < 17 || !/^[a-f0-9]{64}$/.test(module.sha256)) throw new Error("模块校验信息不正确");
    const iv = fromBase64(module.iv);
    const aad = fromBase64(module.aad);
    if (iv.byteLength !== 12 || textDecoder.decode(aad) !== `secure-pages:v1:${module.id}`) throw new Error("模块加密参数不正确");
    modules.set(module.id, { ...module, iv, aad });
  }
  for (const id of Object.keys(EXPECTED_MODULES)) if (!modules.has(id)) throw new Error("模块清单不完整");
  return { manifest, salt, modules };
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, value => value.toString(16).padStart(2, "0")).join("");
}

async function deriveKey(password, manifest, salt) {
  const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: manifest.kdf.hash,
      salt,
      iterations: manifest.kdf.iterations
    },
    material,
    {
      name: "AES-GCM",
      length: manifest.cipher.keyLength
    },
    false,
    ["decrypt"]
  );
}

async function fetchEncrypted(module, version, report) {
  const url = new URL(module.file, document.baseURI);
  url.searchParams.set("v", `${version}-${module.sha256}`);
  const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("无法下载加密模块");
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    report(bytes.byteLength, module.bytes);
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.byteLength;
    report(received, module.bytes);
  }
  const output = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function decryptModule(key, manifest, module, report) {
  const encrypted = await fetchEncrypted(module, manifest.version, report);
  if (encrypted.byteLength !== module.bytes || await sha256Hex(encrypted) !== module.sha256) throw new Error("加密模块校验失败");
  try {
    return await crypto.subtle.decrypt(
      {
        name: manifest.cipher.name,
        iv: module.iv,
        additionalData: module.aad,
        tagLength: manifest.cipher.tagLength
      },
      key,
      encrypted
    );
  } catch (error) {
    throw new Error("密码不正确或加密数据已损坏", { cause: error });
  }
}

function decodeHtml(buffer) {
  try {
    return textDecoder.decode(buffer);
  } catch (error) {
    throw new Error("模块文本编码不正确", { cause: error });
  }
}

function injectAfterHead(html, source) {
  const head = /<head\b[^>]*>/i.exec(html);
  if (!head) return `${source}${html}`;
  const offset = head.index + head[0].length;
  return `${html.slice(0, offset)}${source}${html.slice(offset)}`;
}

function patchScriptQueries(html, query) {
  return html.replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script\s*>)/gi, (match, opening, code, closing) => {
    const replacement = JSON.stringify(query);
    const patched = code
      .replace(/\bwindow\.location\.search\b/g, replacement)
      .replace(/(^|[^\w.])location\.search\b/g, (value, prefix) => `${prefix}${replacement}`);
    return `${opening}${patched}${closing}`;
  });
}

export function prepareModuleHtml(moduleId, html) {
  const query = MODE_QUERIES[moduleId];
  if (!query) return html;
  const mode = moduleId === "inventory" ? "standalone" : "embed";
  const bootstrap = `<script>(function(){var q=${JSON.stringify(query)},m=${JSON.stringify(mode)};window.__SECURE_PAGE_MODE__=m;document.documentElement.dataset.secureMode=m;if(m==="embed"){document.documentElement.dataset.embed="1";document.documentElement.classList.add("is-embedded")}else{document.documentElement.dataset.standalone="1"}try{history.replaceState(null,"",location.pathname+q+location.hash)}catch(e){}})();<\/script>`;
  return injectAfterHead(patchScriptQueries(html, query), bootstrap);
}

export function prepareAppHtml(html) {
  const bridge = `<script>(function(){var p=document,o=p,d;function s(v){try{if(top!==window)top.document.title=String(v||${JSON.stringify(PLATFORM_TITLE)})}catch(e){}}while(o&&!d){d=Object.getOwnPropertyDescriptor(o,"title");o=Object.getPrototypeOf(o)}if(d&&d.get&&d.set)Object.defineProperty(p,"title",{configurable:true,get:function(){return d.get.call(p)},set:function(v){d.set.call(p,v);s(v)}});new MutationObserver(function(){s(p.title)}).observe(document.documentElement,{subtree:true,childList:true,characterData:true});addEventListener("DOMContentLoaded",function(){s(p.title)},{once:true})})();<\/script>`;
  return injectAfterHead(html, bridge);
}

export function replaceModuleTokens(appHtml) {
  let output = appHtml;
  for (const [moduleId, token] of Object.entries(MODULE_TOKENS)) {
    if (!output.includes(token)) throw new Error("平台模块映射不完整");
    const loaderUrl = new URL(LOADER_FILES[moduleId], document.baseURI).href;
    output = output.split(token).join(loaderUrl);
  }
  if (/__SECURE_MODULE_[A-Z_]+__/.test(output)) throw new Error("平台模块映射失败");
  return output;
}

export async function fetchManifest() {
  const response = await fetch(new URL("manifest.json", document.baseURI), { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("无法读取加密清单");
  return response.json();
}

export async function createSecureSession(password, rawManifest, progress = () => {}) {
  if (!globalThis.crypto?.subtle) throw new Error("当前浏览器不支持安全解密");
  const { manifest, salt, modules } = validateManifest(rawManifest);
  progress({ phase: "derive", value: 4, message: "正在验证访问密码" });
  const key = await deriveKey(password, manifest, salt);
  const appModule = modules.get("app");
  const appBuffer = await decryptModule(key, manifest, appModule, (received, total) => {
    progress({ phase: "download", value: 8 + Math.min(70, received / total * 70), message: "正在下载平台入口" });
  });
  progress({ phase: "decrypt", value: 88, message: "正在解密平台入口" });
  let appHtml = prepareAppHtml(replaceModuleTokens(decodeHtml(appBuffer)));
  const moduleHtml = new Map();
  const pending = new Map();
  let disposed = false;

  const loadModule = async (moduleId, moduleProgress = () => {}) => {
    if (disposed) throw new Error("当前安全会话已关闭");
    if (!LOADER_FILES[moduleId]) throw new Error("未知模块");
    if (moduleHtml.has(moduleId)) return moduleHtml.get(moduleId);
    if (pending.has(moduleId)) return pending.get(moduleId);
    const task = (async () => {
      const module = modules.get(moduleId);
      moduleProgress({ phase: "download", message: "正在下载加密模块" });
      let buffer;
      try {
        buffer = await decryptModule(key, manifest, module, (received, total) => {
          moduleProgress({ phase: "download", value: received / total * 80, message: "正在下载加密模块" });
        });
      } catch (error) {
        if (error instanceof Error && error.message === "密码不正确或加密数据已损坏") throw new Error("模块数据损坏或版本不匹配", { cause: error });
        throw error;
      }
      if (disposed) throw new Error("当前安全会话已关闭");
      moduleProgress({ phase: "decrypt", value: 90, message: "正在解密模块" });
      const html = prepareModuleHtml(moduleId, decodeHtml(buffer));
      if (disposed) throw new Error("当前安全会话已关闭");
      moduleHtml.set(moduleId, html);
      moduleProgress({ phase: "ready", value: 100, message: "模块加载完成" });
      return html;
    })().finally(() => pending.delete(moduleId));
    pending.set(moduleId, task);
    return task;
  };

  progress({ phase: "ready", value: 100, message: "平台入口已就绪" });
  return {
    get appHtml() {
      if (disposed) throw new Error("当前安全会话已关闭");
      return appHtml;
    },
    loadModule,
    isLoaded(moduleId) {
      return moduleHtml.has(moduleId);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      appHtml = "";
      pending.clear();
      moduleHtml.clear();
    }
  };
}

function sourceMatchesLoader(source, moduleId, appWindow) {
  try {
    if (!source || source.top !== window) return false;
    let cursor = source;
    let insideApp = false;
    while (cursor && cursor !== window && cursor !== cursor.parent) {
      if (cursor.parent === appWindow) {
        insideApp = true;
        break;
      }
      cursor = cursor.parent;
    }
    if (!insideApp) return false;
    const actual = new URL(source.location.href);
    const expected = new URL(LOADER_FILES[moduleId], document.baseURI);
    return actual.origin === expected.origin && actual.pathname === expected.pathname;
  } catch {
    return false;
  }
}

export function attachModuleBridge(session, appFrame, onState = () => {}) {
  let activeRequests = 0;
  const handler = async event => {
    if (event.origin !== location.origin) return;
    const data = event.data;
    if (!data || data.type !== "secure-module-request" || !LOADER_FILES[data.module] || typeof data.requestId !== "string" || data.requestId.length > 120) return;
    if (!sourceMatchesLoader(event.source, data.module, appFrame.contentWindow)) return;
    activeRequests += 1;
    onState({ busy: true, module: data.module, count: activeRequests, message: "正在安全加载模块" });
    try {
      const html = await session.loadModule(data.module, state => onState({ ...state, busy: true, module: data.module, count: activeRequests }));
      event.source.postMessage({ type: "secure-module-response", requestId: data.requestId, ok: true, html }, event.origin);
    } catch (error) {
      try {
        event.source.postMessage({ type: "secure-module-response", requestId: data.requestId, ok: false, message: error instanceof Error ? error.message : "模块加载失败" }, event.origin);
      } catch {
      }
    } finally {
      activeRequests = Math.max(0, activeRequests - 1);
      onState({ busy: activeRequests > 0, count: activeRequests, message: activeRequests ? "正在安全加载模块" : "" });
    }
  };
  window.addEventListener("message", handler);
  return () => window.removeEventListener("message", handler);
}

function bindShell() {
  const form = document.querySelector("[data-unlock-form]");
  if (!form) return;
  const shell = document.querySelector("[data-login-shell]");
  const workspace = document.querySelector("[data-workspace]");
  const frame = document.querySelector("[data-app-frame]");
  const passwordInput = document.querySelector("[data-password]");
  const toggle = document.querySelector("[data-toggle-password]");
  const submit = document.querySelector("[data-submit]");
  const status = document.querySelector("[data-status]");
  const progressBar = document.querySelector("[data-progress]");
  const workspaceStatus = document.querySelector("[data-workspace-status]");
  const lock = document.querySelector("[data-lock]");
  let manifestPromise = fetchManifest();
  let activeSession = null;
  let detachBridge = null;
  let titleObserver = null;

  const setStatus = (message, type = "") => {
    status.textContent = message;
    status.dataset.type = type;
  };

  const clearSession = () => {
    if (detachBridge) detachBridge();
    if (titleObserver) titleObserver.disconnect();
    if (activeSession) activeSession.dispose();
    detachBridge = null;
    titleObserver = null;
    activeSession = null;
    frame.removeAttribute("srcdoc");
    frame.src = "about:blank";
    workspaceStatus.textContent = "";
  };

  const reset = () => {
    clearSession();
    workspace.hidden = true;
    shell.hidden = false;
    passwordInput.value = "";
    progressBar.value = 0;
    progressBar.hidden = true;
    document.title = LOGIN_TITLE;
    setStatus("请输入访问密码");
    passwordInput.focus();
  };

  const syncTitle = () => {
    try {
      document.title = frame.contentDocument?.title?.trim() || PLATFORM_TITLE;
    } catch {
      document.title = PLATFORM_TITLE;
    }
  };

  const observeAppTitle = () => {
    if (titleObserver) titleObserver.disconnect();
    syncTitle();
    try {
      const target = frame.contentDocument?.head || frame.contentDocument?.documentElement;
      if (!target) return;
      titleObserver = new MutationObserver(syncTitle);
      titleObserver.observe(target, { subtree: true, childList: true, characterData: true });
    } catch {
      titleObserver = null;
    }
  };

  toggle.addEventListener("click", () => {
    const visible = passwordInput.type === "text";
    passwordInput.type = visible ? "password" : "text";
    toggle.textContent = visible ? "显示" : "隐藏";
    toggle.setAttribute("aria-label", visible ? "显示密码" : "隐藏密码");
    passwordInput.focus();
  });

  lock.addEventListener("click", reset);

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const password = passwordInput.value;
    if (!password) {
      setStatus("请输入访问密码", "error");
      passwordInput.focus();
      return;
    }
    submit.disabled = true;
    passwordInput.disabled = true;
    toggle.disabled = true;
    progressBar.hidden = false;
    setStatus("正在准备加密数据");
    try {
      const manifest = await manifestPromise;
      const session = await createSecureSession(password, manifest, state => {
        progressBar.value = state.value;
        setStatus(state.message);
      });
      clearSession();
      activeSession = session;
      detachBridge = attachModuleBridge(session, frame, state => {
        workspaceStatus.textContent = state.busy ? state.message : "";
      });
      shell.hidden = true;
      workspace.hidden = false;
      workspaceStatus.textContent = "正在打开平台";
      await new Promise((resolve, reject) => {
        frame.addEventListener("load", resolve, { once: true });
        frame.addEventListener("error", () => reject(new Error("应用页面加载失败")), { once: true });
        frame.srcdoc = session.appHtml;
      });
      observeAppTitle();
      workspaceStatus.textContent = "";
      passwordInput.value = "";
    } catch (error) {
      clearSession();
      passwordInput.value = "";
      document.title = LOGIN_TITLE;
      setStatus(error instanceof Error ? error.message : "无法打开加密站点", "error");
      progressBar.hidden = true;
      progressBar.value = 0;
      passwordInput.focus();
      if (/清单|下载/.test(String(error))) manifestPromise = fetchManifest();
    } finally {
      submit.disabled = false;
      passwordInput.disabled = false;
      toggle.disabled = false;
    }
  });

  window.addEventListener("beforeunload", clearSession);
  manifestPromise.then(
    () => setStatus("请输入访问密码"),
    error => setStatus(error instanceof Error ? error.message : "站点初始化失败", "error")
  );
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bindShell, { once: true });
else bindShell();
