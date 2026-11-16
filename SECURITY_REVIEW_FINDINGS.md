# Atom ~0.183.0 (Atom Shell 0.21.0) — Validated Security Findings

Scope reviewed: protocol handlers, browser/main IPC, window/`webPreferences`/nodeIntegration, auto-update/Squirrel, command-installer, exception-reporting/metrics. Source under `src/browser/`, `src/window*.coffee`, `src/atom.coffee`, `src/command-installer.coffee`, `src/buffered-process.coffee`, `src/task.coffee`, plus bundled package versions referenced from `package.json`.

Only findings with a realistic end-to-end attack chain are listed. Speculative issues and issues that already require renderer RCE (e.g. `call-window-method` when `nodeIntegration` is already on) are omitted.

---

## Finding 1 — CRITICAL

**Title:** Markdown preview HTML iframe + default `nodeIntegration` → RCE from untrusted Markdown  
**Location:** `src/browser/atom-window.coffee` (window defaults); `static/index.html` (CSP); bundled `markdown-preview@0.137.0` sanitizer  
**Severity:** Critical

### Description

Atom windows are created without disabling Node.js integration. Atom Shell 0.21.0 defaults `nodeIntegration` to enabled. The shell page CSP only restricts `script-src` to `'self'` on `static/index.html`; it does **not** apply to documents navigated inside `<iframe>`/`<object>`.

Bundled `markdown-preview@0.137.0` intentionally renders raw HTML (`sanitize: false` for roaster/marked) and only strips `<script>` and a fixed list of `on*` attributes. **`<iframe>`, `<object>`, and `atom://` / `file://` URLs are allowed.** A Markdown file can frame a local HTML document whose scripts run outside the Markdown sanitizer. With Node available to the window (and historically reachable via `window.top.require` from framed `file://` content in this stack), that yields OS command execution.

### Impact

Remote/untrusted-workspace code execution as the Atom user when a victim opens Markdown preview (README in a cloned repo, or a package README in settings-view in later related issues).

### Attack path

1. Attacker ships a repo containing `README.md` (or any previewed Markdown) plus a payload HTML file, **or** points an iframe at a known local `file://` HTML gadget under the Atom install tree (same class of bug later written up for Atom ~1.20).
2. Victim opens the Markdown file and runs **Markdown Preview**.
3. Preview injects attacker HTML into the Atom UI DOM; iframe navigates to payload HTML.
4. Payload script calls `require('child_process')` (directly or via `window.top.require`) and runs arbitrary commands.

### Evidence

```28:33:src/browser/atom-window.coffee
    options =
      show: false
      title: 'Atom'
      'web-preferences':
        'direct-write': true
        'subpixel-font-scaling': false
```

No `node-integration: false`. Renderer bootstrap uses Node:

```52:52:static/index.js
    require(loadSettings.bootstrapScript);
```

```6:6:static/index.html
  <meta http-equiv="Content-Security-Policy" content="default-src *; script-src 'self'; style-src 'self' 'unsafe-inline';">
```

`markdown-preview@0.137.0` `lib/renderer.coffee` (external package pin): `sanitize: false`, removes only `script` + listed `on*` attrs; `resolveImagePaths` explicitly allows `atom://` URLs through.

### Remediation

- Disable Node in any context that renders untrusted HTML; use a separate `BrowserWindow`/`webview` with `nodeIntegration: false` and tight CSP for previews.
- Sanitize Markdown with a allowlist (e.g. DOMPurify), blocking `iframe`/`object`/`embed` and non-http(s) URLs.
- Do not treat preview HTML as trusted same-origin content.

### Why exploitable

The vulnerable sanitizer is the exact pattern later exploited in Atom Markdown→RCE research; this tree ships that sanitizer version and an editor window with Node enabled by default. User action (preview) is realistic for READMEs in untrusted workspaces.

---

## Finding 2 — HIGH

**Title:** `atom://` protocol handler path traversal → arbitrary local file read  
**Location:** `src/browser/atom-protocol-handler.coffee:31-44`  
**Severity:** High

### Description

The custom `atom:` protocol takes `request.url`, strips the `atom://` prefix (`substr(7)`), runs `path.normalize`, then `path.join`s the result onto package/asset search roots. Normalization does **not** confine the path under those roots; `../` segments escape to arbitrary filesystem locations. Any existing file readable by the Atom process can be served via `RequestFileJob`.

### Impact

Confidentiality break: secrets under the user profile (SSH keys, `.atom` config/storage, tokens on disk, etc.) can be fetched as `atom://…` resources by anything that can cause the Atom webContents to request such a URL (Markdown/HTML preview, themes, packages, etc.).

### Attack path

1. Attacker controls content that becomes a resource URL in Atom (e.g. Markdown/HTML with `<img src="atom://../../.ssh/id_rsa">` or `<iframe src="atom://../../.atom/config.cson">` — markdown-preview allows `atom://` in `src`).
2. Protocol handler resolves e.g. `atom://../../.ssh/id_rsa` with `path.normalize` → `../../.ssh/id_rsa`, then `path.join(~/.atom/packages, …)` → `~/.ssh/id_rsa`.
3. File bytes are returned to the renderer as the resource body (displayed in iframe/object, or consumed by further XSS/gadgets).

### Evidence

```31:44:src/browser/atom-protocol-handler.coffee
  registerAtomProtocol: ->
    protocol.registerProtocol 'atom', (request) =>
      relativePath = path.normalize(request.url.substr(7))

      if relativePath.indexOf('assets/') is 0
        assetsPath = path.join(process.env.ATOM_HOME, relativePath)
        filePath = assetsPath if fs.statSyncNoException(assetsPath).isFile?()

      unless filePath
        for loadPath in @loadPaths
          filePath = path.join(loadPath, relativePath)
          break if fs.statSyncNoException(filePath).isFile?()

      new protocol.RequestFileJob(filePath)
```

Empirical resolution (Linux): `atom://../../../../etc/passwd` → `path.join(packagesDir, '../../../../etc/passwd')` → `/etc/passwd`.

### Remediation

- After join, `fs.realpath` and require `filePath` to stay under an allowlisted root.
- Reject any URL whose normalized relative path starts with `..` or is absolute.
- Prefer `protocol.registerFileProtocol` with explicit path checks.

### Why exploitable

No path-boundary check exists; Markdown preview (bundled) deliberately permits `atom://` resource URLs; the sink serves raw files. No prior RCE required to trigger a fetch—only preview/render of attacker content.

---

## Finding 3 — HIGH

**Title:** Unauthenticated single-instance socket/pipe can force `runSpecs` → arbitrary JS `require`  
**Location:** `src/browser/atom-application.coffee` (`DefaultSocketPath`, `listenForArgumentsFromNewProcess`, `openWithOptions`, `runSpecs`); `spec/spec-suite.coffee`  
**Severity:** High (Windows cross-user / local); High for same-user local pivot on all platforms

### Description

The first Atom instance listens on a fixed IPC endpoint:

- Windows: `\\.\pipe\atom-sock` (global pipe name, no per-user suffix)
- Linux/macOS: `/tmp/atom.sock` (predictable, world-visible directory)

There is no authentication on accepted connections. Payload JSON is parsed and passed to `openWithOptions`. If `test: true`, Atom opens a spec window whose `specDirectory` comes from the client; `spec/spec-suite.coffee` **`require`s every `*-spec.js/coffee` under that directory** inside a Node-enabled window.

Additionally, on Unix, if another local user creates `/tmp/atom.sock` first, a victim Atom becomes a **client**, sends its launch JSON (including `pathsToOpen`) to the attacker, then terminates (DoS + path disclosure). Later Atom versions moved to per-user/version socket names; this version has not.

### Impact

- **RCE as the Atom user** by forcing the running instance to load attacker-controlled spec files.
- Windows: other local users can often connect to a named pipe with a non-user-scoped name.
- Unix: same-user processes can drive the live editor; other users can hijack the socket path before Atom starts.

### Attack path

1. Victim has Atom running (or attacker pre-binds `/tmp/atom.sock` on Unix).
2. Attacker connects to the pipe/socket and writes:
   `{"test":true,"specDirectory":"/tmp/pwn-specs"}`
3. `openWithOptions` → `runSpecs` → `AtomWindow` with `isSpec`/`devMode` and attacker `specDirectory`.
4. `spec-suite.coffee` recursively `require`s `*-spec.js` / `*-spec.coffee` from that directory → attacker code runs with Node privileges of the Atom process.

### Evidence

```17:21:src/browser/atom-application.coffee
DefaultSocketPath =
  if process.platform is 'win32'
    '\\\\.\\pipe\\atom-sock'
  else
    path.join(os.tmpdir(), 'atom.sock')
```

```119:123:src/browser/atom-application.coffee
  listenForArgumentsFromNewProcess: ->
    @deleteSocketFile()
    server = net.createServer (connection) =>
      connection.on 'data', (data) =>
        @openWithOptions(JSON.parse(data))
```

```85:87:src/browser/atom-application.coffee
  openWithOptions: ({pathsToOpen, urlsToOpen, test, pidToKillWhenClosed, devMode, safeMode, newWindow, specDirectory, logFile}) ->
    if test
      @runSpecs({exitWhenDone: true, @resourcePath, specDirectory, logFile})
```

```6:8:spec/spec-suite.coffee
requireSpecs = (specDirectory, specType) ->
  for specFilePath in fs.listTreeSync(specDirectory) when /-spec\.(coffee|js)$/.test specFilePath
    require specFilePath
```

```51:52:spec/spec-suite.coffee
if specDirectory = atom.getLoadSettings().specDirectory
  requireSpecs(specDirectory)
```

### Remediation

- Use a per-user, per-version socket/pipe name; set Unix socket mode `0600`; set an explicit restrictive Windows pipe DACL.
- Authenticate clients (e.g. proof of same uid / shared secret written to a 0600 file).
- Do not expose `test` / `specDirectory` / arbitrary window bootstrap over the single-instance channel; allowlist operations (open paths only).

### Why exploitable

End-to-end: connect → JSON → `runSpecs` → `require` of attacker files. No Atom renderer exploit required. Pipe/socket endpoints are predictable in this version.

---

## Reviewed areas with no validated E2E finding

| Area | Notes |
|------|--------|
| `call-window-method` / IPC `open` → `new AtomWindow(options)` | Dangerous sinks, but the sender is already a Node-enabled renderer; reporting would require prior RCE/XSS equivalent to the impact. |
| Auto-update / Squirrel | Feed URLs are `https://atom.io/api/updates`; no TLS bypass or unsigned-update install path validated in-tree. |
| Command installer | Uses `runas` / `fs.symlink` with argv arrays; no shell concatenation of untrusted input. |
| `BufferedProcess` Win32 quoting | Quoting is fragile, but core has no demonstrated sink feeding untrusted workspace names into `cmd.exe` without a malicious/vulnerable package. |
| exception-reporting@0.24.0 / metrics@0.45.0 | Bugsnag/GA client IDs are expected public post keys; stack traces send paths but no auth-token exfiltration path validated. |

---

## Summary

| # | Severity | Title |
|---|----------|--------|
| 1 | Critical | Markdown HTML iframe + Node integration → RCE |
| 2 | High | `atom://` path traversal arbitrary file read |
| 3 | High | Unauthenticated single-instance IPC → `runSpecs` RCE |
