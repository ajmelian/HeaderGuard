<?php
declare(strict_types=1);

/**
 * Nombre: SecurityHeadersAnalyzer
 * Descripción:
 *   Calcula una puntuación (0-100) según presencia de cabeceras clave y política TLS,
 *   devolviendo checklist de mejoras "copy-paste".
 * Entradas:
 *   - string $url
 *   - array{status:int,headers:array<string,string>,finalUrl:string} $fetch
 *   - array $tlsInfo
 * Salida:
 *   - array{score:int,present:string[],missing:string[],advise:string[],headers:array<string,string>,status:int,finalUrl:string,tls:array}
 * Método de uso:
 *   - $rep = (new SecurityHeadersAnalyzer())->analyze($url, $fetch, $tls);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class SecurityHeadersAnalyzer
{
    /** @param array{status:int,headers:array<string,string>,finalUrl:string} $fetch */
    public function analyze(string $url, array $fetch, array $tls): array
    {
        $h = $fetch['headers'];
        $present = [];
        $missing = [];
        $advise  = [];

        $checks = [
            'strict-transport-security'     => 20,
            'content-security-policy'       => 25,
            'x-content-type-options'        => 10,
            'x-frame-options'               => 8,
            'referrer-policy'               => 8,
            'permissions-policy'            => 8,
            'cross-origin-opener-policy'    => 6,
            'cross-origin-embedder-policy'  => 6,
            'cross-origin-resource-policy'  => 6,
        ];

        $score = 0;
        foreach ($checks as $key => $weight) {
            if (array_key_exists($key, $h)) {
                $present[] = $key;
                $score += $weight;
            } else {
                $missing[] = $key;
            }
        }

        if ($tls['strictTls'] ?? false) $score += 10;
        $score = max(0, min(100, $score));

        if (in_array('strict-transport-security', $missing, true)) {
            $advise[] = 'Strict-Transport-Security: max-age=15552000; includeSubDomains; preload';
        }
        if (in_array('content-security-policy', $missing, true)) {
            $advise[] = "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self'";
        }
        if (in_array('x-content-type-options', $missing, true)) {
            $advise[] = 'X-Content-Type-Options: nosniff';
        }
        if (in_array('x-frame-options', $missing, true)) {
            $advise[] = 'X-Frame-Options: DENY';
        }
        if (in_array('referrer-policy', $missing, true)) {
            $advise[] = 'Referrer-Policy: no-referrer';
        }
        if (in_array('permissions-policy', $missing, true)) {
            $advise[] = 'Permissions-Policy: geolocation=(), camera=(), microphone=()';
        }

        return [
            'score'    => $score,
            'present'  => $present,
            'missing'  => $missing,
            'advise'   => $advise,
            'headers'  => $h,
            'status'   => $fetch['status'],
            'finalUrl' => $fetch['finalUrl'],
            'tls'      => $tls,
        ];
    }
}
