<?php
declare(strict_types=1);

/**
 * Nombre: UrlGuard
 * Descripción:
 *   Valida/normaliza URLs http(s) y previene SSRF bloqueando IPs privadas/reservadas/loopback.
 * Parámetros de entrada:
 *   - string $url
 * Salida:
 *   - string URL normalizada o lanza RuntimeException.
 * Método de uso:
 *   - $safe = (new UrlGuard())->normalizeAndValidate($url);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class UrlGuard
{
    public function normalizeAndValidate(string $url): string
    {
        $url = trim($url);
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new RuntimeException('URL inválida.');
        }
        $p = parse_url($url);
        $scheme = strtolower((string)($p['scheme'] ?? ''));
        if (!in_array($scheme, ['http','https'], true)) {
            throw new RuntimeException('Solo se permite http o https.');
        }
        $host = (string)($p['host'] ?? '');
        if ($host === '') throw new RuntimeException('Host ausente.');

        $ips = gethostbynamel($host) ?: [];
        foreach ($ips as $ip) {
            if ($this->isPrivateOrReserved($ip)) {
                throw new RuntimeException('Destino bloqueado por política anti-SSRF.');
            }
        }
        $port  = isset($p['port']) ? ':'.$p['port'] : '';
        $path  = $p['path'] ?? '/';
        $query = isset($p['query']) ? '?'.$p['query'] : '';
        return $scheme.'://'.$host.$port.$path.$query;
    }

    private function isPrivateOrReserved(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true; // privada o reservada
        }
        return $ip === '127.0.0.1' || $ip === '::1';
    }
}
