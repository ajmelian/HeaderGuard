<?php
declare(strict_types=1);

/**
 * Nombre: Front Controller HeaderGuard
 * Descripción:
 *   Muestra formulario con CSRF y procesa análisis de cabeceras/TLS. Integra IA opcional
 *   (OpenAI/Claude) y registra evidencia en ledger .DAT (hash-chain + Merkle + HMAC).
 * Entradas (POST):
 *   - csrfToken: string (obligatorio)
 *   - url: string (obligatorio)
 *   - useAi: 'on'|null (opcional)
 *   - aiToken: string (si useAi = on)
 *   - consent: 'on' (obligatorio para procesar)
 * Salidas:
 *   - HTML formulario o resultados.
 * Método de uso:
 *   - GET → formulario; POST → procesar.
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */

session_start();
require_once dirname(__DIR__).'/config.php';

spl_autoload_register(static function(string $class): void {
    $path = dirname(__DIR__).'/src/'.$class.'.php';
    if (is_file($path)) require_once $path;
});

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$errors = [];
$csrfSessionKey = '_csrf';

if (!isset($_SESSION[$csrfSessionKey])) {
    $_SESSION[$csrfSessionKey] = bin2hex(random_bytes(32));
}

function render(string $tpl, array $vars = []): void {
    extract($vars, EXTR_OVERWRITE);
    require dirname(__DIR__).'/templates/'.$tpl.'.php';
    exit;
}

if ($method === 'GET') {
    render('form', [
        'csrfToken' => $_SESSION[$csrfSessionKey],
        'prefill'   => ['url' => '', 'useAi' => false, 'aiToken' => '', 'consent' => false],
        'errors'    => []
    ]);
}

if ($method === 'POST') {
    // CSRF
    $csrfPost = $_POST['csrfToken'] ?? '';
    if (!is_string($csrfPost) || !hash_equals($_SESSION[$csrfSessionKey], $csrfPost)) {
        $errors['csrfToken'] = 'Token CSRF inválido. Recarga el formulario.';
    }

    $url     = trim((string)($_POST['url'] ?? ''));
    $useAi   = isset($_POST['useAi']) && $_POST['useAi'] === 'on';
    $aiToken = $useAi ? trim((string)($_POST['aiToken'] ?? '')) : '';
    $consent = isset($_POST['consent']) && $_POST['consent'] === 'on';

    // Consentimiento
    if (!$consent) {
        $errors['consent'] = 'Debes aceptar el tratamiento de datos descrito para continuar.';
    }

    // Validación URL server-side
    $isValidUrl = filter_var($url, FILTER_VALIDATE_URL) !== false;
    $scheme = $isValidUrl ? strtolower((string)parse_url($url, PHP_URL_SCHEME)) : '';
    if (!$isValidUrl || !in_array($scheme, ['http','https'], true)) {
        $errors['url'] = 'Introduce una URL válida con http:// o https://';
    }

    // Validación token IA (si procede)
    if ($useAi) {
        if ($aiToken === '') {
            $errors['aiToken'] = 'Has habilitado IA; introduce el token API.';
        } else {
            $isOpenAi = (bool)preg_match('/^sk-[A-Za-z0-9]{10,}$/', $aiToken);
            $isClaude = (bool)preg_match('/^sk-ant-[A-Za-z0-9]{10,}$/', $aiToken);
            if (!$isOpenAi && !$isClaude) {
                $errors['aiToken'] = 'El token no parece de OpenAI (sk-...) ni de Claude (sk-ant-...).';
            }
        }
    }

    if ($errors) {
        render('form', [
            'csrfToken' => $_SESSION[$csrfSessionKey],
            'prefill'   => ['url' => $url, 'useAi' => $useAi, 'aiToken' => $aiToken, 'consent' => $consent],
            'errors'    => $errors
        ]);
    }

    try {
        // Anti-SSRF y normalización
        $urlGuard = new UrlGuard();
        $safeUrl  = $urlGuard->normalizeAndValidate($url);

        // Fetch + TLS + análisis
        $fetcher   = new HttpHeadersFetcher();
        $tls       = new TlsInspector();
        $analyzer  = new SecurityHeadersAnalyzer();

        $f   = $fetcher->fetchHeadAndHeaders($safeUrl);
        $ti  = $tls->inspect($safeUrl);
        $rep = $analyzer->analyze($safeUrl, $f, $ti);

        // LOG >>> parámetros comunes para el log (antes de IA)
        $clientIp  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        // IA opcional
        $aiText = null;
        $aiUsed = false;
        if ($useAi && $aiToken !== '') {
            $provider = str_starts_with($aiToken, 'sk-ant-') ? 'claude' : 'openai';
            $ai = new AiClient($provider, $aiToken);
            $prompt = "Eres experto en seguridad web. Explica en español, en 8-10 líneas como máximo, "
                    . "qué acciones priorizar para mejorar los headers/TLS de esta URL. Datos: "
                    . json_encode($rep, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            $model = $provider === 'claude' ? 'claude-3-haiku-20240307' : 'gpt-4o-mini';
            $aiText = $ai->complete($prompt, $model, 350);
            $aiUsed = true;
        }

        // Nunca guardar el token
        unset($aiToken);

        // LOG >>> escribir registro (IP hasheada, UA, resultado, AI true/false)
        require_once dirname(__DIR__).'/src/RequestLogger.php';
        $logger = new RequestLogger(REQUEST_LOG_PATH, IP_HASH_SALT);
        $logger->log($clientIp, $userAgent, $safeUrl, $rep, $aiUsed);

        // Evidencia en .DAT (sin PII, solo hash del resumen)
        $txData = [
            'url'       => $safeUrl,
            'score'     => $rep['score'],
            'missing'   => $rep['missing'],
            'strictTls' => $rep['tls']['strictTls'] ?? false,
            'ts'        => time(),
        ];
        $txJson  = json_encode($txData, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        $txHash  = hash('sha256', (string)$txJson);

        // Ledger
        if (!is_dir(dirname(LEDGER_PATH))) {
            mkdir(dirname(LEDGER_PATH), 0750, true);
        }
        $ledger = new TrustChainDat(LEDGER_PATH, LEDGER_HMAC);
        $ledger->appendBlock([$txHash]);
        $ledgerStatus = $ledger->verifyChain();

        render('result', [
            'url'          => $safeUrl,
            'report'       => $rep,
            'aiText'       => $aiText,
            'ledgerStatus' => $ledgerStatus
        ]);

    } catch (Throwable $e) {
        $errors['fatal'] = 'Error durante el análisis: ' . $e->getMessage();
        render('form', [
            'csrfToken' => $_SESSION[$csrfSessionKey],
            'prefill'   => ['url' => $url, 'useAi' => $useAi, 'aiToken' => '', 'consent' => $consent],
            'errors'    => $errors
        ]);
    }
}
