<?php
// fileupload1.php
// Pseudo-browser sandboxed file upload + controlled file-inclusion training endpoint
// v2: adds directory listings for `uploads/` and `uploads/vuln/` while preserving sandboxing

// ----------------------
// Configuration
// ----------------------
$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
$allowedBase = realpath($uploadDir);
$defaultModule = 'module_main';
$pseudoDomain = 'http://www.hack.me';
$pseudoDomainPattern = '#^https?://(?:www\.)?hack\.me#i';

$vulnDir = $uploadDir . '/vuln_files';
if (!is_dir($vulnDir)) mkdir($vulnDir, 0777, true);

// training sample files (only created if missing)
if (!file_exists($vulnDir . '/secret.txt')) file_put_contents($vulnDir . '/secret.txt', "FLAG{training_flag}\nThis file is inside the training vuln folder.");
if (!file_exists($vulnDir . '/shell.php')) file_put_contents($vulnDir . '/shell.php', "<?php echo '<p>Simulated shell included: shell.php</p>'; ?>");

// ----------------------
// Helpers / security
// ----------------------
function send_403_and_exit() {
    header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
    echo "<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='refresh' content='2;url=" . htmlspecialchars($_SERVER['PHP_SELF']) . "'>";
    echo "<style>body{font-family:Arial;text-align:center;padding:40px} h1{color:#c33}</style></head><body><h1>403 Forbidden</h1><p>Sandbox escape attempt blocked.</p><p>Returning to module...</p></body></html>";
    exit;
}
function is_malicious_input($s) {
    if ($s === null) return true;
    if (preg_match('#\x00#', $s)) return true;
    if (preg_match('#\.\.#', $s)) return true;
    if (preg_match('#[\\\\]#', $s)) return true;
    if (preg_match('#^/#', $s)) return true;
    return false;
}
function mime_for_file($path) {
    if (function_exists('finfo_open')) {
        $f = finfo_open(FILEINFO_MIME_TYPE);
        $m = finfo_file($f, $path);
        finfo_close($f);
        return $m ?: 'application/octet-stream';
    }
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $map = ['html'=>'text/html','htm'=>'text/html','php'=>'text/html','txt'=>'text/plain','js'=>'application/javascript','css'=>'text/css','json'=>'application/json','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','svg'=>'image/svg+xml','pdf'=>'application/pdf'];
    return $map[$ext] ?? 'application/octet-stream';
}
function resolve_case_insensitive($baseDir, $rel) {
    $rel = preg_replace('#^/+|/+$#','',$rel);
    if ($rel === '') return realpath($baseDir);
    $parts = explode('/', $rel);
    $cwd = rtrim($baseDir, '/');
    foreach ($parts as $part) {
        if ($part === '' || $part === '.') continue;
        if ($part === '..' || preg_match('#\x00|\\\\#', $part)) return false;
        $found = false;
        $entries = @scandir($cwd);
        if ($entries === false) return false;
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            if (strcasecmp($entry, $part) === 0) { $cwd .= '/' . $entry; $found = true; break; }
        }
        if (!$found) return false;
    }
    $real = realpath($cwd);
    if ($real === false) return false;
    $baseReal = realpath($baseDir);
    if (strpos($real, $baseReal) !== 0) return false;
    return $real;
}
function safe_execute_php_cli($file, $allowedDir) {
    if (!is_file($file) || !is_readable($file)) return false;
    $phpbin = defined('PHP_BINARY') ? PHP_BINARY : trim(shell_exec('which php 2>/dev/null'));
    if (!$phpbin) return false;
    $open_basedir = $allowedDir;
    $disabled = 'exec,passthru,shell_exec,system,popen,proc_open,pcntl_exec';
    $cmd = escapeshellcmd($phpbin) . ' -n -d open_basedir=' . escapeshellarg($open_basedir)
         . ' -d disable_functions=' . escapeshellarg($disabled) . ' -d allow_url_include=0 -d allow_url_fopen=0 ' . escapeshellarg($file);
    $descriptors = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    $cwd = $allowedDir;
    $proc = @proc_open($cmd, $descriptors, $pipes, $cwd);
    if (!is_resource($proc)) return false;
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $output=''; $err=''; $start=time();
    while (true) {
        $o = stream_get_contents($pipes[1]); $e = stream_get_contents($pipes[2]);
        if ($o!=='') $output.=$o; if ($e!=='') $err.=$e;
        $status = proc_get_status($proc);
        if (!$status['running']) break;
        if (time()-$start>5) { proc_terminate($proc, 9); break; }
        usleep(100000);
    }
    fclose($pipes[1]); fclose($pipes[2]); $ret = proc_close($proc);
    if ($err!=='') $output .= "\n<!-- STDERR:\n" . htmlspecialchars($err) . "\n-->";
    return $output;
}

// ----------------------
// Upload handling (module UI)
$uploadMsg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename($_FILES['file']['name']);
    if (preg_match('#[\/\\\\\x00]#', $name) || strpos($name, '..') !== false) {
        $uploadMsg = "<div style='padding:10px;background:#ffecec;border:1px solid #a33;margin:10px 0;'>❌ Invalid filename.</div>";
    } else {
        $target = $uploadDir . '/' . $name;
        if (@move_uploaded_file($_FILES['file']['tmp_name'], $target)) { @chmod($target, 0644); $uploadMsg = "<div style='padding:10px;background:#e6ffed;border:1px solid #2a8a3a;margin:10px 0;'>✅ Uploaded: " . htmlspecialchars($name) . "</div>"; }
        else $uploadMsg = "<div style='padding:10px;background:#ffecec;border:1px solid #a33;margin:10px 0;'>❌ Upload failed.</div>";
    }
}

// ----------------------
// Serve / proxy logic
if (isset($_GET['serve'])) {
    $serveRaw = (string)$_GET['serve'];

    // Upload module form and (when listing disabled) no file listing. We'll keep the form here too.
    if ($serveRaw === '__' . $defaultModule) {
        header('Content-Type: text/html; charset=utf-8'); ?>
        <!doctype html><html><head><meta charset="utf-8"><title>Upload Module (sandbox)</title>
        <style>body{font-family:Arial;padding:12px}.hint{color:#666}</style></head><body>
        <h2>📁 Upload Module (sandbox)</h2>
        <form method="post" enctype="multipart/form-data" action="<?= htmlspecialchars($_SERVER['PHP_SELF'] . '?serve=__' . $defaultModule) ?>">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
        <?= $uploadMsg ?: '' ?>
        <p class="hint">This module intentionally does NOT list uploaded files unless you explicitly navigate to <code>uploads/</code>.</p>
        <p class="hint">Try: <code>http://www.hack.me/uploads/</code> or <code>uploads/vuln/</code></p>
        <script>document.addEventListener('click',function(ev){var a=ev.target.closest&&ev.target.closest('a'); if(!a) return; ev.preventDefault(); parent.postMessage({type:'navigate', href:a.href}, '*');}, true);</script>
        </body></html><?php exit;
    }

    // Serve directory listing for uploads (crappy php-style listing)
    if ($serveRaw === '__list_uploads') {
        header('Content-Type: text/html; charset=utf-8');
        $entries = array_values(array_filter(scandir($uploadDir), function($f){ return $f !== '.' && $f !== '..'; }));
        echo "<!doctype html><html><head><meta charset='utf-8'><title>Index of /uploads/</title><style>body{font-family:monospace;padding:12px;background:#fff} a{display:block;padding:4px 0}</style></head><body><h2>Index of /uploads/</h2><pre>";
        foreach ($entries as $e) {
            $full = realpath($uploadDir . '/' . $e);
            if (!$full || strpos($full, realpath($uploadDir)) !== 0) continue; // safety
            $display = htmlspecialchars($e . (is_dir($full) ? '/' : ''));
            $link = htmlspecialchars($pseudoDomain . '/uploads/' . rawurlencode($e) . (is_dir($full) ? '/' : ''));
            echo "<a href=\"$link\">$display</a>\n";
        }
        echo "</pre><script>document.addEventListener('click',function(ev){var a=ev.target.closest&&ev.target.closest('a'); if(!a)return; ev.preventDefault(); parent.postMessage({type:'navigate', href:a.href}, '*');},true);</script></body></html>";
        exit;
    }

    // Serve directory listing for vuln folder
    if ($serveRaw === '__list_vuln') {
        header('Content-Type: text/html; charset=utf-8');
        $entries = array_values(array_filter(scandir($vulnDir), function($f){ return $f !== '.' && $f !== '..'; }));
        echo "<!doctype html><html><head><meta charset='utf-8'><title>Index of /uploads/vuln/</title><style>body{font-family:monospace;padding:12px;background:#fff} a{display:block;padding:4px 0}</style></head><body><h2>Index of /uploads/vuln/</h2><pre>";
        foreach ($entries as $e) {
            $full = realpath($vulnDir . '/' . $e);
            if (!$full || strpos($full, realpath($vulnDir)) !== 0) continue;
            $display = htmlspecialchars($e);
            $link = htmlspecialchars($pseudoDomain . '/uploads/vuln/' . rawurlencode($e));
            echo "<a href=\"$link\">$display</a>\n";
        }
        echo "</pre><script>document.addEventListener('click',function(ev){var a=ev.target.closest&&ev.target.closest('a'); if(!a)return; ev.preventDefault(); parent.postMessage({type:'navigate', href:a.href}, '*');},true);</script></body></html>";
        exit;
    }

    // Serve vuln file (explicitly allowed inside vulnDir)
    if (preg_match('#^vuln/(.+)$#i', $serveRaw, $m)) {
        $candidate = $m[1];
        if (is_malicious_input($candidate)) send_403_and_exit();
        $full = resolve_case_insensitive($vulnDir, $candidate);
        if (!$full) send_403_and_exit();
        $mime = mime_for_file($full); $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
        if (in_array($ext, ['php','html','htm','txt'])) {
            if ($ext === 'php') {
                $out = safe_execute_php_cli($full, $vulnDir);
                $content = ($out === false) ? '<pre>' . htmlspecialchars(file_get_contents($full)) . '</pre>' : $out;
            } else $content = file_get_contents($full);
            $inj = "<script>document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a'); if(!a) return; e.preventDefault(); parent.postMessage({type:'navigate', href:a.href}, '*');}, true);</script>";
            if (preg_match('#</body\s*>#i',$content)) $content = preg_replace('#</body\s*>#i',$inj.'</body>',$content,1); else $content .= $inj;
            header('Content-Type: ' . $mime . '; charset=utf-8'); echo $content; exit;
        } else { header('Content-Type: ' . $mime); header('Content-Length: ' . filesize($full)); readfile($full); exit; }
    }

    // Otherwise serve uploaded file (case-insensitive resolution inside uploads)
    if (is_malicious_input($serveRaw)) send_403_and_exit();
    $full = resolve_case_insensitive($uploadDir, $serveRaw);
    if (!$full) send_403_and_exit();
    $mime = mime_for_file($full); $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
    if (in_array($ext, ['php','html','htm','txt'])) {
        if ($ext === 'php') {
            $out = safe_execute_php_cli($full, $uploadDir);
            $content = ($out === false) ? '<pre>' . htmlspecialchars(file_get_contents($full)) . '</pre>' : $out;
        } else $content = file_get_contents($full);
        $inj = "<script>document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a'); if(!a) return; e.preventDefault(); parent.postMessage({type:'navigate', href:a.href}, '*');}, true);document.addEventListener('submit',function(e){e.preventDefault(); alert('POSTs from served pages disabled.');}, true);</script>";
        if (preg_match('#</body\s*>#i',$content)) $content = preg_replace('#</body\s*>#i',$inj.'</body>',$content,1); else $content .= $inj;
        header('Content-Type: ' . $mime . '; charset=utf-8'); echo $content; exit;
    } else { header('Content-Type: ' . $mime); header('Content-Length: ' . filesize($full)); readfile($full); exit; }
}

// ----------------------
// Main UI render (parent pseudo-browser)
$iframeSrc = '?serve=__' . $defaultModule;
$displayAddress = '';
if (isset($_GET['path'])) {
    $rawInput = (string)$_GET['path'];
    // Strip allowed domain if present
    $stripped = preg_replace($pseudoDomainPattern, '', $rawInput);
    $stripped = preg_replace('#^/+|/+$#','', $stripped);
    if (is_malicious_input($stripped)) send_403_and_exit();

    // Normalize (case-insensitive)
    $normalized = null;
    $low = strtolower($stripped);
    if ($low === '' || in_array($low, ['upload','uploads'])) { $normalized = 'uploads'; }
    elseif (preg_match('#^(?:upload|uploads)/(.*)$#i',$stripped,$m)) { $normalized = 'uploads/' . $m[1]; }
    elseif (!str_contains($stripped,'/')) { $normalized = 'uploads/' . $stripped; }
    else { $normalized = $stripped; }

    if ($normalized === 'uploads') {
        // show directory listing for uploads
        $iframeSrc = '?serve=__list_uploads';
        $displayAddress = $pseudoDomain . '/uploads/';
    } elseif (preg_match('#^uploads/vuln(?:/?)$#i', $normalized)) {
        // show listing of vuln folder
        $iframeSrc = '?serve=__list_vuln';
        $displayAddress = $pseudoDomain . '/uploads/vuln/';
    } elseif (preg_match('#^uploads/vuln/(.+)$#i', $normalized, $m)) {
        $candidate = $m[1];
        if (is_malicious_input($candidate)) send_403_and_exit();
        $full = resolve_case_insensitive($vulnDir, $candidate);
        if (!$full) send_403_and_exit();
        $iframeSrc = '?serve=' . 'vuln/' . rawurlencode(basename($full));
        $displayAddress = $pseudoDomain . '/uploads/vuln/' . basename($full);
    } elseif (preg_match('#^uploads/(.+)$#i', $normalized, $m)) {
        $candidate = $m[1];
        $full = resolve_case_insensitive($uploadDir, $candidate);
        if (!$full) send_403_and_exit();
        $iframeSrc = '?serve=' . rawurlencode(basename($full));
        $displayAddress = $pseudoDomain . '/uploads/' . basename($full);
    } else send_403_and_exit();
} else {
    $displayAddress = $pseudoDomain . '/';
}
?><!doctype html>
<html>
<head><meta charset="utf-8"><title>HackMe - File Inclusion Lab (safe)</title>
<style>:root{--maxw:920px}body{font-family:Arial,Helvetica,sans-serif;background:#f4f4f9;margin:0;padding:20px;display:flex;justify-content:center}.browser{width:100%;max-width:var(--maxw);height:640px;border-radius:8px;box-shadow:0 8px 30px rgba(0,0,0,0.12);overflow:hidden;background:#fff;border:2px solid #333;display:flex;flex-direction:column}.urlbar{background:#f0f0f0;border-bottom:1px solid #ddd;padding:10px}.urlbar input{width:100%;padding:8px 10px;border:1px solid #bbb;border-radius:6px;font-family:monospace;font-size:14px}.framewrap{flex:1;overflow:hidden}iframe{width:100%;height:100%;border:0}.note{font-size:12px;color:#666;margin-top:6px}</style>
</head>
<body>
<div class="browser" role="region" aria-label="Pseudo browser sandbox">
    <div class="urlbar">
        <input id="address" type="text" value="<?= htmlspecialchars($displayAddress) ?>" placeholder="<?= htmlspecialchars($pseudoDomain . '/') ?>">
        <div class="note">Type <code>uploads/</code> to see a crude directory listing; <code>uploads/vuln/</code> to see vuln files; files execute only inside the sandbox.</div>
    </div>
    <div class="framewrap">
        <iframe id="viewport" src="<?= htmlspecialchars($iframeSrc) ?>" sandbox="allow-scripts allow-forms allow-same-origin"></iframe>
    </div>
</div>

<script>
const allowedDomainPattern = /^https?:\/\/(?:www\.)?hack\.me(\/.*)?$/i;
function normalizeInput(raw) {
    raw = String(raw || '').trim();
    var m = raw.match(allowedDomainPattern);
    if (m) raw = m[1] || '/';
    raw = raw.replace(/^\/+|\/+$/g,'');
    var low = raw.toLowerCase();
    if (low === '' || low === 'upload' || low === 'uploads') return 'uploads';
    var r = raw.replace(/^\/+|\/+$/g,'');
    var match = r.match(/^(?:upload|uploads)\/(.+)$/i);
    if (match) return 'uploads/' + match[1];
    if (!r.includes('/')) return 'uploads/' + r;
    return r;
}
document.getElementById('address').addEventListener('keydown', function(e){
    if (e.key === 'Enter') {
        var val = this.value.trim();
        if (/^https?:\/\//i.test(val) && !allowedDomainPattern.test(val)) { alert('❌ External domains are forbidden. Only http://www.hack.me/* is allowed.'); return; }
        if (/(\.\.|\\|%00)/.test(val)) { alert('❌ Forbidden path syntax detected.'); return; }
        var norm = normalizeInput(val);
        if (norm === 'uploads' || norm.startsWith('uploads/')) {
            window.location = '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=' + encodeURIComponent(norm);
        } else alert('❌ Only <?= addslashes($pseudoDomain) ?>uploads/... (or upload/uploads aliases) are allowed.');
    }
});
window.addEventListener('message', function(ev){
    try {
        var data = ev.data || {};
        if (data.type === 'navigate' && typeof data.href === 'string') {
            var href = data.href;
            if (/^https?:\/\//i.test(href) && !allowedDomainPattern.test(href)) { window.location = '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=' + encodeURIComponent('..'); return; }
            var m = href.match(allowedDomainPattern);
            if (m) href = m[1] || '/';
            href = href.replace(/^\/+|\/+$/g,'');
            if (/(\.\.|\\|%00)/.test(href)) { window.location = '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=' + encodeURIComponent('..'); return; }
            var normalized = normalizeInput(href);
            if (normalized === 'uploads' || normalized.startsWith('uploads/')) {
                document.getElementById('address').value = '<?= addslashes($pseudoDomain) ?>/' + normalized.replace(/^uploads\/?/,'uploads/');
                window.location = '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=' + encodeURIComponent(normalized);
            } else {
                window.location = '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=' + encodeURIComponent(normalized);
            }
        }
    } catch(e) { console.error(e); }
}, false);
</script>
</body>
</html>
