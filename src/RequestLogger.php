<?php
declare(strict_types=1);

/**
 * Nombre: RequestLogger
 * Descripción de la funcionalidad:
 *   Registra en un fichero NDJSON (.ndjson) cada análisis realizado: IP hasheada, userAgent,
 *   fecha/hora (UTC), URL solicitada, finalUrl, resultado (status, score, strictTls,
 *   missingCount) y si se usó IA (ai=true/false). Nunca persiste tokens.
 * Parámetros de entrada:
 *   - string $logPath        Ruta al fichero .ndjson.
 *   - string $ipHashSalt     Salt para hashear IP con SHA-256.
 *   - string $clientIp       IP del solicitante (no se guarda en claro).
 *   - string $userAgent      Agente de usuario del solicitante.
 *   - string $url            URL solicitada.
 *   - array  $report         Informe del análisis (status, score, tls.strictTls, missing[]).
 *   - bool   $aiUsed         Indica si se invocó IA (true/false). Nunca se guarda el token.
 * Salida:
 *   - bool   True si se pudo escribir la línea.
 * Método de uso:
 *   - (new RequestLogger(REQUEST_LOG_PATH, IP_HASH_SALT))->log(...);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class RequestLogger
{
    public function __construct(
        private string $logPath,
        private string $ipHashSalt
    ) {}

    /**
     * @param array{
     *   status:int, finalUrl:string, score:int,
     *   tls:array{strictTls?:bool}, missing:array<int,string>
     * } $report
     */
    public function log(
        string $clientIp,
        string $userAgent,
        string $url,
        array $report,
        bool $aiUsed
    ): bool {
        $ipHash = hash('sha256', $clientIp . $this->ipHashSalt);

        $ua      = mb_substr($userAgent, 0, 512);
        $status  = (int)($report['status'] ?? 0);
        $score   = (int)($report['score'] ?? 0);
        $final   = (string)($report['finalUrl'] ?? $url);
        $strict  = (bool)($report['tls']['strictTls'] ?? false);
        $missing = (array)($report['missing'] ?? []);
        $missingCount = count($missing);

        $row = [
            'ts'          => gmdate('c'),
            'ipHash'      => $ipHash,
            'userAgent'   => $ua,
            'url'         => $url,
            'finalUrl'    => $final,
            'result'      => [
                'status'       => $status,
                'score'        => $score,
                'strictTls'    => $strict,
                'missingCount' => $missingCount,
            ],
            'ai'          => $aiUsed,
        ];

        $json = json_encode($row, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }

        $dir = dirname($this->logPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }

        return (bool)file_put_contents($this->logPath, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
