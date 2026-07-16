const MANIFEST_VERSION = 2;
const CIPHER_CACHE_NAME = "secure-pages-v2-ciphertext";
const EXPECTED_MODULES = Object.freeze({
  app: "app-v2.enc",
  quote: "quote-v2.enc",
  inventory: "inventory-v2.enc",
  pom: "pom-v2.enc",
  mechatronics: "mechatronics-v2.enc"
});

const EXPECTED_ASSETS = Object.freeze({
  "quote-images": "quote-images-v2.enc"
});

const MODULE_TOKENS = Object.freeze({
  quote: "__SECURE_MODULE_QUOTE__",
  inventory: "__SECURE_MODULE_INVENTORY__",
  pom: "__SECURE_MODULE_POM__",
  mechatronics: "__SECURE_MODULE_MECHATRONICS__"
});

const LOADER_FILES = Object.freeze({
  quote: "module-quote-v2.html",
  inventory: "module-inventory-v2.html",
  pom: "module-pom-v2.html",
  mechatronics: "module-mechatronics-v2.html"
});

const MODE_QUERIES = Object.freeze({
  inventory: "?standalone=1",
  pom: "?embed=1",
  mechatronics: "?embed=1"
});

const PREFETCH_ORDER = Object.freeze(["quote", "inventory", "pom", "mechatronics"]);
const MAX_RECORD_BYTES = 256 * 1024 * 1024;
const ACCOUNT_NAME = "lu.wei";
const SESSION_DB_NAME = "secure-pages-session-v1";
const SESSION_STORE_NAME = "sessions";
const SESSION_RECORD_ID = "primary";
const SESSION_REVOKED_KEY = "secure-pages-session-revoked-v1";
const LOGIN_TITLE = "安全访问 | 备件库存结构分析平台";
const PLATFORM_TITLE = "备件库存结构分析平台";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const cipherJobs = new Map();
let cipherCachePromise;

function fromBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error("加密清单格式不正确");
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
  return output;
}

function validateRecord(record, expectedFiles, seen) {
  if (!record || expectedFiles[record.id] !== record.file || seen.has(record.id)) throw new Error("加密清单记录不正确");
  if (!Number.isInteger(record.bytes) || record.bytes < 17 || record.bytes > MAX_RECORD_BYTES || !Number.isInteger(record.plainBytes) || record.plainBytes < 1 || record.plainBytes > MAX_RECORD_BYTES || !/^[a-f0-9]{64}$/.test(record.sha256)) throw new Error("模块校验信息不正确");
  const iv = fromBase64(record.iv);
  const aad = fromBase64(record.aad);
  if (iv.byteLength !== 12 || textDecoder.decode(aad) !== `secure-pages:v${MANIFEST_VERSION}:${record.id}`) throw new Error("模块加密参数不正确");
  seen.add(record.id);
  return { ...record, iv, aad };
}

function validateManifest(manifest) {
  if (!manifest || manifest.version !== MANIFEST_VERSION || manifest.entry !== "app" || manifest.encoding !== "utf-8" || manifest.compression?.name !== "gzip") throw new Error("站点版本不兼容");
  if (manifest.kdf?.name !== "PBKDF2" || manifest.kdf?.hash !== "SHA-256" || !Number.isInteger(manifest.kdf?.iterations) || manifest.kdf.iterations < 100000) throw new Error("密钥参数不正确");
  if (manifest.cipher?.name !== "AES-GCM" || manifest.cipher?.keyLength !== 256 || manifest.cipher?.tagLength !== 128) throw new Error("加密参数不正确");
  const salt = fromBase64(manifest.kdf.salt);
  if (salt.byteLength < 16) throw new Error("密钥参数不正确");
  if (!Array.isArray(manifest.modules) || manifest.modules.length !== Object.keys(EXPECTED_MODULES).length) throw new Error("模块清单不完整");
  if (!Array.isArray(manifest.assets) || manifest.assets.length !== Object.keys(EXPECTED_ASSETS).length) throw new Error("资源清单不完整");
  const moduleIds = new Set();
  const assetIds = new Set();
  const modules = new Map(manifest.modules.map(record => {
    const validated = validateRecord(record, EXPECTED_MODULES, moduleIds);
    return [validated.id, validated];
  }));
  const assets = new Map(manifest.assets.map(record => {
    const validated = validateRecord(record, EXPECTED_ASSETS, assetIds);
    return [validated.id, validated];
  }));
  for (const id of Object.keys(EXPECTED_MODULES)) if (!modules.has(id)) throw new Error("模块清单不完整");
  for (const id of Object.keys(EXPECTED_ASSETS)) if (!assets.has(id)) throw new Error("资源清单不完整");
  return { manifest, salt, modules, assets };
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

function rememberedSessionVersion(manifest) {
  const app = Array.isArray(manifest?.modules) ? manifest.modules.find(record => record?.id === "app") : null;
  return `${manifest?.version || ""}:${manifest?.kdf?.salt || ""}:${manifest?.kdf?.iterations || ""}:${app?.sha256 || ""}`;
}

function openRememberedSessionDb() {
  if (!("indexedDB" in globalThis)) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SESSION_DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(SESSION_STORE_NAME)) request.result.createObjectStore(SESSION_STORE_NAME, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("无法打开设备登录存储"));
    request.onblocked = () => reject(new Error("设备登录存储正在被占用"));
  });
}

async function useRememberedSessionStore(mode, operation) {
  const db = await openRememberedSessionDb();
  if (!db) return null;
  try {
    const transaction = db.transaction(SESSION_STORE_NAME, mode);
    const completed = new Promise((resolve, reject) => {
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error || new Error("设备登录存储失败"));
      transaction.onabort = () => reject(transaction.error || new Error("设备登录存储已取消"));
    });
    const result = await operation(transaction.objectStore(SESSION_STORE_NAME));
    await completed;
    return result;
  } finally {
    db.close();
  }
}

function storeRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("设备登录存储失败"));
  });
}

function rememberedSessionIsRevoked() {
  try {
    return localStorage.getItem(SESSION_REVOKED_KEY) === "1";
  } catch {
    return false;
  }
}

function setRememberedSessionRevoked(revoked) {
  try {
    if (revoked) localStorage.setItem(SESSION_REVOKED_KEY, "1");
    else localStorage.removeItem(SESSION_REVOKED_KEY);
  } catch {
  }
}

async function saveRememberedSession(key, manifest) {
  const record = {
    id: SESSION_RECORD_ID,
    account: ACCOUNT_NAME,
    version: rememberedSessionVersion(manifest),
    key,
    savedAt: Date.now()
  };
  const result = await useRememberedSessionStore("readwrite", store => storeRequest(store.put(record)));
  if (result === null) throw new Error("当前浏览器不支持长期登录");
  setRememberedSessionRevoked(false);
}

async function clearRememberedSession() {
  setRememberedSessionRevoked(true);
  if (!("indexedDB" in globalThis)) return true;
  try {
    await useRememberedSessionStore("readwrite", store => storeRequest(store.delete(SESSION_RECORD_ID)));
    return true;
  } catch {
    return false;
  }
}

async function readRememberedSession(manifest) {
  if (rememberedSessionIsRevoked()) {
    await clearRememberedSession();
    return null;
  }
  try {
    const record = await useRememberedSessionStore("readonly", store => storeRequest(store.get(SESSION_RECORD_ID)));
    if (!record) return null;
    const valid = record.account === ACCOUNT_NAME
      && record.version === rememberedSessionVersion(manifest)
      && record.key?.type === "secret"
      && record.key?.algorithm?.name === "AES-GCM"
      && Array.from(record.key?.usages || []).includes("decrypt");
    if (valid) return record;
    await clearRememberedSession();
    return null;
  } catch {
    return null;
  }
}

function recordUrl(record) {
  const url = new URL(record.file, document.baseURI);
  url.searchParams.set("v", `${MANIFEST_VERSION}-${record.sha256}`);
  return url;
}

async function openCipherCache() {
  if (!("caches" in globalThis)) return null;
  if (!cipherCachePromise) {
    cipherCachePromise = globalThis.caches.open(CIPHER_CACHE_NAME).catch(() => null);
  }
  return cipherCachePromise;
}

async function readExactBytes(response, expectedBytes, report, meta) {
  const contentLength = Number(response.headers.get("content-length"));
  const contentEncoding = response.headers.get("content-encoding");
  if ((!contentEncoding || contentEncoding === "identity") && Number.isFinite(contentLength) && contentLength > 0 && contentLength !== expectedBytes) throw new Error("加密模块长度不正确");
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength !== expectedBytes) throw new Error("加密模块长度不正确");
    report(bytes.byteLength, expectedBytes, meta);
    return bytes;
  }
  const output = new Uint8Array(expectedBytes);
  const reader = response.body.getReader();
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (received + value.byteLength > expectedBytes) {
      await reader.cancel().catch(() => {});
      throw new Error("加密模块长度不正确");
    }
    output.set(value, received);
    received += value.byteLength;
    report(received, expectedBytes, meta);
  }
  if (received !== expectedBytes) throw new Error("加密模块长度不正确");
  return output;
}

async function readVerifiedCache(cache, url, record, report) {
  if (!cache) return null;
  let response;
  try {
    response = await cache.match(url.href);
  } catch {
    return null;
  }
  if (!response) return null;
  try {
    const bytes = await readExactBytes(response, record.bytes, () => {}, { cached: true });
    if (await sha256Hex(bytes) !== record.sha256) throw new Error("加密模块校验失败");
    report(record.bytes, record.bytes, { cached: true });
    return bytes;
  } catch {
    try {
      await cache.delete(url.href);
    } catch {
    }
    return null;
  }
}

async function fetchVerifiedCipher(record, report) {
  const url = recordUrl(record);
  const cache = await openCipherCache();
  const cached = await readVerifiedCache(cache, url, record, report);
  if (cached) return cached;
  const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("无法下载加密模块");
  const bytes = await readExactBytes(response, record.bytes, report, { cached: false });
  if (await sha256Hex(bytes) !== record.sha256) throw new Error("加密模块校验失败");
  if (cache) {
    try {
      await cache.put(url.href, new Response(bytes, {
        status: 200,
        headers: {
          "content-type": "application/octet-stream",
          "content-length": String(bytes.byteLength)
        }
      }));
    } catch {
    }
  }
  return bytes;
}

function fetchEncrypted(record, report = () => {}) {
  const key = recordUrl(record).href;
  let job = cipherJobs.get(key);
  if (job) {
    job.listeners.add(report);
    if (job.last) {
      try {
        report(...job.last);
      } catch {
      }
    }
    return job.promise.finally(() => job.listeners.delete(report));
  }
  job = { listeners: new Set([report]), last: null, promise: null };
  const notify = (received, total, meta) => {
    job.last = [received, total, meta];
    for (const listener of job.listeners) {
      try {
        listener(received, total, meta);
      } catch {
      }
    }
  };
  job.promise = fetchVerifiedCipher(record, notify).finally(() => {
    if (cipherJobs.get(key) === job) cipherJobs.delete(key);
  });
  cipherJobs.set(key, job);
  return job.promise.finally(() => job.listeners.delete(report));
}

async function pruneCipherCache(records) {
  const cache = await openCipherCache();
  if (!cache) return;
  const allowed = new Set(records.map(record => recordUrl(record).href));
  let requests;
  try {
    requests = await cache.keys();
  } catch {
    return;
  }
  await Promise.all(requests.filter(request => !allowed.has(request.url)).map(request => cache.delete(request).catch(() => false)));
}

async function decryptCipher(key, manifest, record, encrypted) {
  try {
    return await crypto.subtle.decrypt(
      {
        name: manifest.cipher.name,
        iv: record.iv,
        additionalData: record.aad,
        tagLength: manifest.cipher.tagLength
      },
      key,
      encrypted
    );
  } catch (error) {
    throw new Error("密码不正确或加密数据已损坏", { cause: error });
  }
}

async function decompressGzip(buffer, expectedBytes) {
  if (typeof DecompressionStream !== "function") throw new Error("当前浏览器版本不支持安全压缩数据");
  let reader;
  try {
    const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
    reader = stream.getReader();
    const output = new Uint8Array(expectedBytes);
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (received + value.byteLength > expectedBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("解压后数据长度不正确");
      }
      output.set(value, received);
      received += value.byteLength;
    }
    if (received !== expectedBytes) throw new Error("解压后数据长度不正确");
    return output.buffer;
  } catch (error) {
    if (error instanceof Error && /浏览器版本|数据长度/.test(error.message)) throw error;
    throw new Error("加密模块解压失败", { cause: error });
  } finally {
    if (reader) reader.releaseLock();
  }
}

function decodeText(buffer) {
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
  const response = await fetch(new URL("manifest-v2.json", document.baseURI), { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("无法读取加密清单");
  return response.json();
}

async function createSecureSessionCore(rawManifest, keyProvider, progress, deriveMessage) {
  if (!globalThis.crypto?.subtle) throw new Error("当前浏览器不支持安全解密");
  const { manifest, salt, modules, assets } = validateManifest(rawManifest);
  void pruneCipherCache([...modules.values(), ...assets.values()]);
  progress({ phase: "derive", value: 4, message: deriveMessage });
  const appModule = modules.get("app");
  const keyPromise = Promise.resolve().then(() => keyProvider(manifest, salt));
  const encryptedPromise = fetchEncrypted(appModule, (received, total, meta) => {
    progress({ phase: "download", value: 8 + Math.min(68, received / total * 68), message: meta?.cached ? "正在读取本机加密缓存" : "正在下载平台入口" });
  });
  let key = await keyPromise;
  const encryptedApp = await encryptedPromise;
  progress({ phase: "decrypt", value: 82, message: "正在解密平台入口" });
  const compressedApp = await decryptCipher(key, manifest, appModule, encryptedApp);
  progress({ phase: "decompress", value: 92, message: "正在解压平台入口" });
  const appBuffer = await decompressGzip(compressedApp, appModule.plainBytes);
  let appHtml = prepareAppHtml(replaceModuleTokens(decodeText(appBuffer)));
  const moduleHtml = new Map();
  const modulePending = new Map();
  const assetPending = new Map();
  let disposed = false;

  const loadModule = async (moduleId, moduleProgress = () => {}) => {
    if (disposed) throw new Error("当前安全会话已关闭");
    if (!LOADER_FILES[moduleId]) throw new Error("未知模块");
    if (moduleHtml.has(moduleId)) return moduleHtml.get(moduleId);
    if (modulePending.has(moduleId)) return modulePending.get(moduleId);
    const task = (async () => {
      const record = modules.get(moduleId);
      moduleProgress({ phase: "download", value: 0, message: "正在准备加密模块" });
      let encrypted;
      try {
        encrypted = await fetchEncrypted(record, (received, total, meta) => {
          moduleProgress({ phase: "download", value: received / total * 78, message: meta?.cached ? "正在读取本机加密缓存" : "正在下载加密模块" });
        });
      } catch (error) {
        throw error;
      }
      if (disposed || !key) throw new Error("当前安全会话已关闭");
      moduleProgress({ phase: "decrypt", value: 84, message: "正在解密模块" });
      let compressed;
      try {
        compressed = await decryptCipher(key, manifest, record, encrypted);
      } catch (error) {
        if (error instanceof Error && error.message === "密码不正确或加密数据已损坏") throw new Error("模块数据损坏或版本不匹配", { cause: error });
        throw error;
      }
      if (disposed) throw new Error("当前安全会话已关闭");
      moduleProgress({ phase: "decompress", value: 94, message: "正在解压模块" });
      const buffer = await decompressGzip(compressed, record.plainBytes);
      if (disposed) throw new Error("当前安全会话已关闭");
      const html = prepareModuleHtml(moduleId, decodeText(buffer));
      if (disposed) throw new Error("当前安全会话已关闭");
      moduleHtml.set(moduleId, html);
      moduleProgress({ phase: "ready", value: 100, message: "模块加载完成" });
      return html;
    })().finally(() => modulePending.delete(moduleId));
    modulePending.set(moduleId, task);
    return task;
  };

  const loadAsset = async (assetId, assetProgress = () => {}) => {
    if (disposed) throw new Error("当前安全会话已关闭");
    if (!assets.has(assetId)) throw new Error("未知加密资源");
    if (assetPending.has(assetId)) return assetPending.get(assetId);
    const task = (async () => {
      const record = assets.get(assetId);
      assetProgress({ phase: "download", value: 0, message: "正在准备图片资料" });
      const encrypted = await fetchEncrypted(record, (received, total, meta) => {
        assetProgress({ phase: "download", value: received / total * 78, message: meta?.cached ? "正在读取本机图片缓存" : "正在下载加密图片资料" });
      });
      if (disposed || !key) throw new Error("当前安全会话已关闭");
      assetProgress({ phase: "decrypt", value: 84, message: "正在解密图片资料" });
      const compressed = await decryptCipher(key, manifest, record, encrypted);
      if (disposed) throw new Error("当前安全会话已关闭");
      assetProgress({ phase: "decompress", value: 94, message: "正在解压图片资料" });
      const buffer = await decompressGzip(compressed, record.plainBytes);
      if (disposed) throw new Error("当前安全会话已关闭");
      assetProgress({ phase: "ready", value: 100, message: "图片资料加载完成" });
      return decodeText(buffer);
    })().finally(() => assetPending.delete(assetId));
    assetPending.set(assetId, task);
    return task;
  };

  const prefetchModules = async (moduleIds = PREFETCH_ORDER) => {
    for (const moduleId of moduleIds) {
      if (disposed) return;
      const record = modules.get(moduleId);
      if (!record || moduleId === "app" || moduleHtml.has(moduleId) || modulePending.has(moduleId)) continue;
      try {
        await fetchEncrypted(record);
      } catch {
      }
    }
  };

  progress({ phase: "ready", value: 100, message: "平台入口已就绪" });
  return {
    get appHtml() {
      if (disposed) throw new Error("当前安全会话已关闭");
      return appHtml;
    },
    loadModule,
    loadAsset,
    prefetchModules,
    async remember() {
      if (disposed || !key) throw new Error("当前安全会话已关闭");
      await saveRememberedSession(key, manifest);
    },
    isLoaded(moduleId) {
      return moduleHtml.has(moduleId);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      appHtml = "";
      key = null;
      modulePending.clear();
      assetPending.clear();
      moduleHtml.clear();
    }
  };
}

export async function createSecureSession(password, rawManifest, progress = () => {}) {
  return createSecureSessionCore(rawManifest, (manifest, salt) => deriveKey(password, manifest, salt), progress, "正在验证访问密码");
}

export async function createSecureSessionWithKey(key, rawManifest, progress = () => {}) {
  const valid = key?.type === "secret" && key?.algorithm?.name === "AES-GCM" && Array.from(key?.usages || []).includes("decrypt");
  if (!valid) throw new Error("保存的登录已失效");
  return createSecureSessionCore(rawManifest, () => key, progress, "正在恢复设备登录");
}

function loaderFrameForSource(source, moduleId, appWindow) {
  try {
    if (!source || source.top !== window) return null;
    let cursor = source;
    let insideApp = false;
    while (cursor && cursor !== window && cursor !== cursor.parent) {
      if (cursor.parent === appWindow) {
        insideApp = true;
        break;
      }
      cursor = cursor.parent;
    }
    if (!insideApp) return null;
    const actual = new URL(source.location.href);
    const expected = new URL(LOADER_FILES[moduleId], document.baseURI);
    if (actual.origin !== expected.origin || actual.pathname !== expected.pathname) return null;
    const frame = source.frameElement;
    if (!frame || frame.ownerDocument?.defaultView !== source.parent) return null;
    return frame;
  } catch {
    return null;
  }
}

function trustedQuoteWindow(source, appFrame) {
  try {
    if (!source || source.top !== window || source.parent !== appFrame.contentWindow) return false;
    const frame = source.frameElement;
    if (!frame || frame.ownerDocument !== appFrame.contentDocument || !frame.classList.contains("quoteFrame")) return false;
    const sourceUrl = frame.dataset.src || frame.getAttribute("src") || "";
    const expected = new URL(LOADER_FILES.quote, document.baseURI);
    const actual = new URL(sourceUrl, appFrame.contentWindow.location.href);
    return actual.origin === expected.origin && actual.pathname === expected.pathname;
  } catch {
    return false;
  }
}

function validRequestId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 120;
}

export function attachModuleBridge(session, appFrame, onState = () => {}) {
  let activeRequests = 0;
  const begin = (kind, id) => {
    activeRequests += 1;
    onState({ busy: true, kind, module: id, count: activeRequests, message: kind === "asset" ? "正在安全加载图片资料" : "正在安全加载模块" });
  };
  const update = (kind, id, state) => {
    onState({ ...state, busy: true, kind, module: id, count: activeRequests });
  };
  const finish = () => {
    activeRequests = Math.max(0, activeRequests - 1);
    onState({ busy: activeRequests > 0, count: activeRequests, message: activeRequests ? "正在安全加载数据" : "" });
  };
  const handler = async event => {
    if (event.origin !== location.origin) return;
    const data = event.data;
    if (!data || !validRequestId(data.requestId)) return;
    if (data.type === "secure-module-request" && LOADER_FILES[data.module]) {
      const targetFrame = loaderFrameForSource(event.source, data.module, appFrame.contentWindow);
      if (!targetFrame) return;
      begin("module", data.module);
      try {
        const html = await session.loadModule(data.module, state => update("module", data.module, state));
        const currentFrame = loaderFrameForSource(event.source, data.module, appFrame.contentWindow);
        if (currentFrame !== targetFrame) throw new Error("模块容器已发生变化");
        currentFrame.srcdoc = html;
      } catch (error) {
        try {
          event.source.postMessage({ type: "secure-module-response", requestId: data.requestId, ok: false, message: error instanceof Error ? error.message : "模块加载失败" }, event.origin);
        } catch {
        }
      } finally {
        finish();
      }
      return;
    }
    if (data.type === "secure-asset-request" && data.asset === "quote-images" && trustedQuoteWindow(event.source, appFrame)) {
      begin("asset", data.asset);
      try {
        const jsonText = await session.loadAsset(data.asset, state => update("asset", data.asset, state));
        if (!trustedQuoteWindow(event.source, appFrame)) throw new Error("报价单容器已发生变化");
        const apply = event.source.__SECURE_APPLY_QUOTE_IMAGES__;
        if (typeof apply !== "function") throw new Error("图片资料接收器不可用");
        await apply.call(event.source, jsonText, data.requestId);
      } catch (error) {
        try {
          event.source.postMessage({ type: "secure-asset-response", requestId: data.requestId, ok: false, message: error instanceof Error ? error.message : "图片资料加载失败" }, event.origin);
        } catch {
        }
      } finally {
        finish();
      }
    }
  };
  window.addEventListener("message", handler);
  return () => window.removeEventListener("message", handler);
}

function connectionAllowsPrefetch() {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (!connection) return true;
  return !connection.saveData && connection.effectiveType !== "slow-2g" && connection.effectiveType !== "2g";
}

function bindShell() {
  const form = document.querySelector("[data-unlock-form]");
  if (!form) return;
  const shell = document.querySelector("[data-login-shell]");
  const workspace = document.querySelector("[data-workspace]");
  const frame = document.querySelector("[data-app-frame]");
  const accountInput = document.querySelector("[data-account]");
  const passwordInput = document.querySelector("[data-password]");
  const rememberInput = document.querySelector("[data-remember]");
  const toggle = document.querySelector("[data-toggle-password]");
  const submit = document.querySelector("[data-submit]");
  const status = document.querySelector("[data-status]");
  const progressBar = document.querySelector("[data-progress]");
  const workspaceStatus = document.querySelector("[data-workspace-status]");
  const lock = document.querySelector("[data-lock]");
  const characterScene = document.querySelector("[data-character-scene]");
  const characterBodies = characterScene ? Array.from(characterScene.querySelectorAll("[data-character]")) : [];
  let manifestPromise = fetchManifest();
  let activeSession = null;
  let detachBridge = null;
  let titleObserver = null;
  let prefetchHandle = null;
  let prefetchIsIdle = false;
  let unlocking = false;
  let startupChecking = true;
  let startupRestoreCancelled = false;
  let sessionEpoch = 0;
  let frameGeneration = 0;
  let cancelFrameActivation = null;
  let characterPointerFrame = 0;
  let characterPointerX = 0;
  let characterPointerY = 0;
  let characterCenters = null;
  let characterSceneEnabled = false;
  let characterMotionRunning = false;
  let characterSceneDisposed = false;
  let characterFocusFrame = 0;
  let mutualLookTimer = 0;
  let peekDelayTimer = 0;
  let peekCloseTimer = 0;
  const reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const blinkProfiles = characterBodies
    .filter(body => body.dataset.character === "purple" || body.dataset.character === "dark")
    .map(body => ({
      body,
      delayTimer: 0,
      closeTimer: 0,
      minDelay: body.dataset.character === "purple" ? 2800 : 3600,
      maxDelay: body.dataset.character === "purple" ? 6200 : 7600
    }));

  const setStatus = (message, type = "", field = "") => {
    status.textContent = message;
    status.dataset.type = type;
    form.dataset.state = field;
    accountInput.setAttribute("aria-invalid", String(field === "account-error"));
    passwordInput.setAttribute("aria-invalid", String(field === "password-error"));
  };

  const setBusy = (busy, label = "正在验证") => {
    unlocking = busy;
    form.setAttribute("aria-busy", String(busy));
    submit.disabled = busy;
    submit.dataset.busy = String(busy);
    submit.textContent = busy ? label : "进入平台";
    accountInput.disabled = busy;
    passwordInput.disabled = busy;
    rememberInput.disabled = busy;
    toggle.disabled = busy;
    syncCharacterScene();
    refreshCharacterMotion();
  };

  const syncCharacterScene = () => {
    if (!characterScene) return;
    const passwordFilled = passwordInput.value.length > 0;
    const nextState = unlocking ? "busy" : passwordFilled
      ? passwordInput.type === "text" && passwordFilled ? "revealed" : "password"
      : document.activeElement === accountInput ? "account" : "idle";
    if (characterScene.dataset.state !== nextState) {
      characterScene.dataset.state = nextState;
      characterCenters = null;
      if (nextState === "account") startMutualLook();
      else clearMutualLook();
      if (nextState === "revealed") startCharacterPeek();
      else clearCharacterPeek();
      if (nextState === "revealed" || nextState === "busy") resetCharacterPointer();
    }
  };

  const resetCharacterPointer = () => {
    for (const body of characterBodies) {
      body.style.setProperty("--look-x", "0px");
      body.style.setProperty("--look-y", "0px");
      body.style.setProperty("--face-x", "0px");
      body.style.setProperty("--face-y", "0px");
      body.style.setProperty("--body-skew", "0deg");
    }
  };

  const clearCharacterBlinks = () => {
    for (const profile of blinkProfiles) {
      if (profile.delayTimer) clearTimeout(profile.delayTimer);
      if (profile.closeTimer) clearTimeout(profile.closeTimer);
      profile.delayTimer = 0;
      profile.closeTimer = 0;
      delete profile.body.dataset.blinking;
    }
  };

  const canRunCharacterMotion = () => characterSceneEnabled
    && !characterSceneDisposed
    && !shell.hidden
    && !document.hidden
    && !unlocking
    && !reducedMotionQuery.matches;

  const canTrackCharacterPointer = () => canRunCharacterMotion()
    && characterScene.dataset.state !== "revealed"
    && characterScene.dataset.state !== "busy";

  const clearMutualLook = () => {
    if (mutualLookTimer) clearTimeout(mutualLookTimer);
    mutualLookTimer = 0;
    delete characterScene.dataset.looking;
  };

  const startMutualLook = () => {
    clearMutualLook();
    if (!canRunCharacterMotion() || characterScene.dataset.state !== "account") return;
    characterScene.dataset.looking = "true";
    mutualLookTimer = window.setTimeout(() => {
      mutualLookTimer = 0;
      delete characterScene.dataset.looking;
    }, 800);
  };

  const clearCharacterPeek = () => {
    if (peekDelayTimer) clearTimeout(peekDelayTimer);
    if (peekCloseTimer) clearTimeout(peekCloseTimer);
    peekDelayTimer = 0;
    peekCloseTimer = 0;
    const purple = characterScene.querySelector('[data-character="purple"]');
    if (purple) delete purple.dataset.peeking;
  };

  const scheduleCharacterPeek = () => {
    if (!canRunCharacterMotion() || characterScene.dataset.state !== "revealed") return;
    peekDelayTimer = window.setTimeout(() => {
      peekDelayTimer = 0;
      if (!canRunCharacterMotion() || characterScene.dataset.state !== "revealed") return;
      const purple = characterScene.querySelector('[data-character="purple"]');
      if (purple) purple.dataset.peeking = "true";
      peekCloseTimer = window.setTimeout(() => {
        peekCloseTimer = 0;
        if (purple) delete purple.dataset.peeking;
        scheduleCharacterPeek();
      }, 800);
    }, 2000 + Math.random() * 3000);
  };

  const startCharacterPeek = () => {
    clearCharacterPeek();
    scheduleCharacterPeek();
  };

  const clearCharacterSpecials = () => {
    clearMutualLook();
    clearCharacterPeek();
  };

  const startCharacterSpecials = () => {
    if (characterScene.dataset.state === "account") startMutualLook();
    if (characterScene.dataset.state === "revealed") startCharacterPeek();
  };

  const scheduleCharacterBlink = profile => {
    if (!canRunCharacterMotion()) return;
    const delay = profile.minDelay + Math.random() * (profile.maxDelay - profile.minDelay);
    profile.delayTimer = window.setTimeout(() => {
      profile.delayTimer = 0;
      if (!canRunCharacterMotion()) return;
      profile.body.dataset.blinking = "true";
      profile.closeTimer = window.setTimeout(() => {
        profile.closeTimer = 0;
        delete profile.body.dataset.blinking;
        scheduleCharacterBlink(profile);
      }, 120 + Math.random() * 45);
    }, delay);
  };

  const startCharacterBlinks = () => {
    clearCharacterBlinks();
    for (const profile of blinkProfiles) scheduleCharacterBlink(profile);
  };

  const updateCharacterPointer = () => {
    characterPointerFrame = 0;
    if (!canTrackCharacterPointer()) {
      resetCharacterPointer();
      return;
    }
    if (!characterCenters) {
      characterCenters = characterBodies.map(body => {
        const rect = body.getBoundingClientRect();
        return {
          body,
          x: rect.left + rect.width / 2,
          y: rect.top + rect.height / 3
        };
      });
    }
    for (const center of characterCenters) {
      const { body } = center;
      const deltaX = characterPointerX - center.x;
      const deltaY = characterPointerY - center.y;
      const angle = Math.atan2(deltaY, deltaX);
      const strength = Math.min(1, Math.hypot(deltaX, deltaY) / 220);
      const maxLook = body.dataset.character === "dark" ? 4 : 5;
      const lookX = Math.cos(angle) * maxLook * strength;
      const lookY = Math.sin(angle) * maxLook * strength;
      const skew = Math.max(-5, Math.min(5, -deltaX / 120));
      const faceX = Math.max(-12, Math.min(12, deltaX / 22));
      const faceY = Math.max(-8, Math.min(8, deltaY / 30));
      body.style.setProperty("--look-x", `${lookX.toFixed(2)}px`);
      body.style.setProperty("--look-y", `${lookY.toFixed(2)}px`);
      body.style.setProperty("--face-x", `${faceX.toFixed(2)}px`);
      body.style.setProperty("--face-y", `${faceY.toFixed(2)}px`);
      body.style.setProperty("--body-skew", `${skew.toFixed(2)}deg`);
    }
  };

  const trackCharacterPointer = event => {
    if (!canTrackCharacterPointer() || event.pointerType && event.pointerType !== "mouse") return;
    characterPointerX = event.clientX;
    characterPointerY = event.clientY;
    if (!characterPointerFrame) characterPointerFrame = requestAnimationFrame(updateCharacterPointer);
  };

  const handleCharacterPointerExit = event => {
    if (event.relatedTarget === null) resetCharacterPointer();
  };

  const stopCharacterMotion = () => {
    if (characterPointerFrame) cancelAnimationFrame(characterPointerFrame);
    characterPointerFrame = 0;
    clearCharacterBlinks();
    clearCharacterSpecials();
    if (characterMotionRunning) {
      window.removeEventListener("pointermove", trackCharacterPointer);
      window.removeEventListener("pointerout", handleCharacterPointerExit);
      characterMotionRunning = false;
    }
    resetCharacterPointer();
  };

  function refreshCharacterMotion() {
    if (!canRunCharacterMotion()) {
      stopCharacterMotion();
      return;
    }
    if (characterMotionRunning) return;
    characterMotionRunning = true;
    window.addEventListener("pointermove", trackCharacterPointer, { passive: true });
    window.addEventListener("pointerout", handleCharacterPointerExit, { passive: true });
    startCharacterBlinks();
    startCharacterSpecials();
  }

  const pauseCharacterScene = () => {
    characterSceneEnabled = false;
    stopCharacterMotion();
  };

  const resumeCharacterScene = () => {
    if (!characterScene || characterSceneDisposed) return;
    characterSceneEnabled = true;
    characterCenters = null;
    syncCharacterScene();
    refreshCharacterMotion();
  };

  const handleCharacterVisibility = () => refreshCharacterMotion();

  const handleCharacterGeometryChange = () => {
    characterCenters = null;
  };

  const handleCharacterFocusChange = () => {
    if (characterFocusFrame) cancelAnimationFrame(characterFocusFrame);
    characterFocusFrame = requestAnimationFrame(() => {
      characterFocusFrame = 0;
      syncCharacterScene();
    });
  };

  const disposeCharacterScene = () => {
    if (!characterScene || characterSceneDisposed) return;
    characterSceneDisposed = true;
    pauseCharacterScene();
    if (characterFocusFrame) cancelAnimationFrame(characterFocusFrame);
    characterFocusFrame = 0;
    document.removeEventListener("visibilitychange", handleCharacterVisibility);
    window.removeEventListener("resize", handleCharacterGeometryChange);
    characterScene.removeEventListener("transitionend", handleCharacterGeometryChange);
    form.removeEventListener("focusin", handleCharacterFocusChange);
    form.removeEventListener("focusout", handleCharacterFocusChange);
    if (typeof reducedMotionQuery.removeEventListener === "function") {
      reducedMotionQuery.removeEventListener("change", handleCharacterVisibility);
    } else {
      reducedMotionQuery.removeListener(handleCharacterVisibility);
    }
  };

  const cancelPrefetch = () => {
    if (prefetchHandle === null) return;
    if (prefetchIsIdle && typeof cancelIdleCallback === "function") cancelIdleCallback(prefetchHandle);
    else clearTimeout(prefetchHandle);
    prefetchHandle = null;
    prefetchIsIdle = false;
  };

  const schedulePrefetch = session => {
    cancelPrefetch();
    if (!connectionAllowsPrefetch()) return;
    const run = () => {
      prefetchHandle = null;
      prefetchIsIdle = false;
      if (activeSession === session) void session.prefetchModules(PREFETCH_ORDER);
    };
    if (typeof requestIdleCallback === "function") {
      prefetchIsIdle = true;
      prefetchHandle = requestIdleCallback(run, { timeout: 4000 });
    } else {
      prefetchHandle = setTimeout(run, 1200);
    }
  };

  const clearSession = ({ resetFrame = true } = {}) => {
    frameGeneration += 1;
    if (cancelFrameActivation) {
      const cancel = cancelFrameActivation;
      cancelFrameActivation = null;
      cancel();
    }
    cancelPrefetch();
    if (detachBridge) detachBridge();
    if (titleObserver) titleObserver.disconnect();
    if (activeSession) activeSession.dispose();
    detachBridge = null;
    titleObserver = null;
    activeSession = null;
    try {
      frame.contentWindow?.stop();
    } catch {
    }
    if (resetFrame && (frame.hasAttribute("srcdoc") || frame.src !== "about:blank")) {
      frame.removeAttribute("srcdoc");
      frame.src = "about:blank";
    }
    workspaceStatus.textContent = "";
  };

  const resetPasswordVisibility = () => {
    passwordInput.type = "password";
    toggle.dataset.visible = "false";
    toggle.setAttribute("aria-pressed", "false");
    toggle.setAttribute("aria-label", "显示密码");
    syncCharacterScene();
  };

  const reset = () => {
    clearSession();
    workspace.hidden = true;
    shell.hidden = false;
    accountInput.value = ACCOUNT_NAME;
    passwordInput.value = "";
    resetPasswordVisibility();
    progressBar.value = 0;
    progressBar.hidden = true;
    document.title = LOGIN_TITLE;
    setStatus("请输入账号与平台访问密码");
    passwordInput.focus();
    resumeCharacterScene();
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
    toggle.dataset.visible = String(!visible);
    toggle.setAttribute("aria-pressed", String(!visible));
    toggle.setAttribute("aria-label", visible ? "显示密码" : "隐藏密码");
    passwordInput.focus();
    syncCharacterScene();
  });

  const clearFieldError = () => {
    if (status.dataset.type === "error") setStatus("请输入账号与平台访问密码");
  };

  accountInput.addEventListener("input", () => {
    clearFieldError();
    syncCharacterScene();
  });
  passwordInput.addEventListener("input", () => {
    clearFieldError();
    syncCharacterScene();
  });
  if (characterScene) {
    form.addEventListener("focusin", handleCharacterFocusChange);
    form.addEventListener("focusout", handleCharacterFocusChange);
    document.addEventListener("visibilitychange", handleCharacterVisibility);
    window.addEventListener("resize", handleCharacterGeometryChange, { passive: true });
    characterScene.addEventListener("transitionend", handleCharacterGeometryChange);
    if (typeof reducedMotionQuery.addEventListener === "function") {
      reducedMotionQuery.addEventListener("change", handleCharacterVisibility);
    } else {
      reducedMotionQuery.addListener(handleCharacterVisibility);
    }
    resumeCharacterScene();
  }
  rememberInput.addEventListener("change", () => {
    if (!rememberInput.checked) {
      void clearRememberedSession().then(cleared => {
        if (!cleared && !shell.hidden) setStatus("长期登录已停用，但设备登录数据清理失败", "error", "session-error");
      });
    }
  });

  lock.addEventListener("click", () => {
    sessionEpoch += 1;
    setRememberedSessionRevoked(true);
    rememberInput.checked = false;
    reset();
    void clearRememberedSession().then(cleared => {
      if (!cleared) setStatus("平台已锁定，但设备登录数据清理失败，请清理浏览器站点数据", "error", "session-error");
    });
  });

  const activateSession = async session => {
    clearSession({ resetFrame: false });
    const generation = frameGeneration;
    activeSession = session;
    detachBridge = attachModuleBridge(session, frame, state => {
      workspaceStatus.textContent = state.busy ? state.message : "";
    });
    shell.hidden = true;
    workspace.hidden = false;
    pauseCharacterScene();
    workspaceStatus.textContent = "正在打开平台";
    await new Promise((resolve, reject) => {
      let cancelActivation = null;
      const cleanup = () => {
        frame.removeEventListener("load", handleLoad);
        frame.removeEventListener("error", handleError);
        if (cancelFrameActivation === cancelActivation) cancelFrameActivation = null;
      };
      cancelActivation = () => {
        cleanup();
        reject(new Error("登录已取消"));
      };
      const handleLoad = () => {
        if (generation !== frameGeneration) {
          cleanup();
          reject(new Error("登录已取消"));
          return;
        }
        try {
          if (frame.contentWindow?.location?.href !== "about:srcdoc" || frame.contentDocument?.readyState !== "complete" || frame.srcdoc !== session.appHtml) return;
        } catch {
          return;
        }
        cleanup();
        resolve();
      };
      const handleError = () => {
        if (generation !== frameGeneration) {
          cleanup();
          reject(new Error("登录已取消"));
          return;
        }
        cleanup();
        reject(new Error("应用页面加载失败"));
      };
      cancelFrameActivation = cancelActivation;
      frame.addEventListener("load", handleLoad);
      frame.addEventListener("error", handleError);
      frame.srcdoc = session.appHtml;
    });
    observeAppTitle();
    workspaceStatus.textContent = "";
  };

  const unlock = async ({ password = "", key = null, remember = false, automatic = false }) => {
    if (unlocking) return false;
    const operationEpoch = sessionEpoch;
    setBusy(true, automatic ? "正在恢复登录" : "正在验证");
    progressBar.hidden = false;
    setStatus(automatic ? "正在恢复设备登录" : "正在准备加密数据");
    let session = null;
    try {
      const manifest = await manifestPromise;
      const updateProgress = state => {
        progressBar.value = state.value;
        setStatus(state.message);
      };
      session = key
        ? await createSecureSessionWithKey(key, manifest, updateProgress)
        : await createSecureSession(password, manifest, updateProgress);
      await activateSession(session);
      if (remember && !automatic) {
        try {
          await session.remember();
        } catch {
          if (activeSession === session) workspaceStatus.textContent = "当前浏览器未能保存长期登录";
          setTimeout(() => {
            if (activeSession === session) workspaceStatus.textContent = "";
          }, 4000);
        }
      } else if (!automatic) {
        const cleared = await clearRememberedSession();
        if (!cleared) workspaceStatus.textContent = "长期登录已停用，但设备登录数据清理失败";
      }
      if (operationEpoch !== sessionEpoch || activeSession !== session) {
        await clearRememberedSession();
        return false;
      }
      passwordInput.value = "";
      schedulePrefetch(session);
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : "无法打开加密站点";
      if (operationEpoch !== sessionEpoch || message === "登录已取消") return false;
      clearSession();
      workspace.hidden = true;
      shell.hidden = false;
      passwordInput.value = "";
      resetPasswordVisibility();
      document.title = LOGIN_TITLE;
      if (automatic) {
        if (/密码不正确|登录已失效|数据已损坏|版本不匹配/.test(message)) await clearRememberedSession();
        setStatus(/下载|清单/.test(message) ? message : "保存的登录已失效，请重新登录", "error", "session-error");
      } else {
        setStatus(message, "error", /密码不正确/.test(message) ? "password-error" : "session-error");
      }
      progressBar.hidden = true;
      progressBar.value = 0;
      requestAnimationFrame(() => {
        if (!shell.hidden) passwordInput.focus();
      });
      resumeCharacterScene();
      if (/清单|下载/.test(String(error))) manifestPromise = fetchManifest();
      return false;
    } finally {
      setBusy(false);
    }
  };

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (startupChecking) {
      startupRestoreCancelled = true;
      return;
    }
    const account = accountInput.value.trim().toLowerCase();
    const password = passwordInput.value;
    if (!account) {
      setStatus("请输入账号", "error", "account-error");
      accountInput.focus();
      return;
    }
    if (account !== ACCOUNT_NAME) {
      setStatus("账号或密码不正确", "error", "account-error");
      accountInput.focus();
      return;
    }
    if (!password) {
      setStatus("请输入平台访问密码", "error", "password-error");
      passwordInput.focus();
      return;
    }
    await unlock({ password, remember: rememberInput.checked });
  });

  setBusy(true, "正在检查");
  setStatus("正在检查已保存的登录");
  window.addEventListener("beforeunload", () => {
    disposeCharacterScene();
    clearSession();
  }, { once: true });
  manifestPromise.then(
    async manifest => {
      const remembered = await readRememberedSession(manifest);
      if (startupRestoreCancelled || !remembered) {
        startupChecking = false;
        setBusy(false);
        setStatus("请输入账号与平台访问密码");
        return;
      }
      accountInput.value = ACCOUNT_NAME;
      rememberInput.checked = true;
      startupChecking = false;
      setBusy(false);
      await unlock({ key: remembered.key, remember: true, automatic: true });
    },
    error => {
      startupChecking = false;
      setBusy(false);
      setStatus(error instanceof Error ? error.message : "站点初始化失败", "error");
    }
  );
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bindShell, { once: true });
else bindShell();
