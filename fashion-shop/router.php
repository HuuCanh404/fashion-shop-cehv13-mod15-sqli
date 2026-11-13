<?php
$uriPath = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
$query = (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '') ? ('?' . $_SERVER['QUERY_STRING']) : '';

if ($uriPath === '/' || $uriPath === '' || $uriPath === '/shopweb' || $uriPath === '/shopweb/') {
    header('Location: /shopweb/index.php' . $query);
    exit;
}

if (strpos($uriPath, '/shopweb/') === 0) {
    $rel = substr($uriPath, strlen('/shopweb'));
    $baseReal = realpath(__DIR__);
    $candidate = $baseReal . DIRECTORY_SEPARATOR . ltrim(str_replace('/', DIRECTORY_SEPARATOR, $rel), DIRECTORY_SEPARATOR);
    $realTarget = realpath($candidate);

    if ($realTarget === false || strpos($realTarget, $baseReal) !== 0) {
        http_response_code(404);
        echo '404 Not Found';
        return true;
    }

    if (is_dir($realTarget)) {
        header('Location: /shopweb' . rtrim($rel, '/') . '/index.php' . $query);
        exit;
    }

    $ext = strtolower(pathinfo($realTarget, PATHINFO_EXTENSION));
    if ($ext === 'php') {
        chdir(dirname($realTarget));
        $_SERVER['SCRIPT_FILENAME'] = $realTarget;
        $_SERVER['SCRIPT_NAME'] = $uriPath;
        $_SERVER['PHP_SELF'] = $uriPath;
        require $realTarget;
        return true;
    }

    $mimeMap = [
        'css' => 'text/css; charset=utf-8',
        'js' => 'application/javascript; charset=utf-8',
        'json' => 'application/json; charset=utf-8',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'webp' => 'image/webp',
        'gif' => 'image/gif',
        'svg' => 'image/svg+xml',
        'ico' => 'image/x-icon',
        'woff' => 'font/woff',
        'woff2' => 'font/woff2',
        'ttf' => 'font/ttf',
    ];
    if (isset($mimeMap[$ext])) {
        header('Content-Type: ' . $mimeMap[$ext]);
    }
    readfile($realTarget);
    return true;
}

if (file_exists(__DIR__ . $uriPath)) {
    if (is_dir(__DIR__ . $uriPath)) {
        header('Location: /shopweb' . rtrim($uriPath, '/') . '/index.php' . $query);
        exit;
    }
    header('Location: /shopweb' . $uriPath . $query);
    exit;
}

return false;
