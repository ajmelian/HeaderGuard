<?php
declare(strict_types=1);

/**
 * Nombre: TlsInspector
 * Descripción:
 *   Inspección rápida de TLS y certificado del servidor (CN, Issuer, validez, SAN).
 * Parámetros de entrada:
 *   - string $url https://...
 * Salida:
 *   - array{tlsVersion:?string, cert:?array{cn?:string,issuer?:string,notBefore?:string,notAfter?:string,san?:string[]}, strictTls:bool}
 * Método de uso:
 *   - $info = (new TlsInspector())->inspect($url);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class TlsInspector
{
    /** @return array{tlsVersion:?string, cert:?array, strictTls:bool} */
    public function inspect(string $url): array
    {
        $p = parse_url($url);
        if (($p['scheme'] ?? '') !== 'https') {
            return ['tlsVersion'=>null, 'cert'=>null, 'strictTls'=>false];
        }
        $host = (string)$p['host'];
        $port = (int)($p['port'] ?? 443);

        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => true,
                'verify_peer_name'  => true,
                'SNI_enabled'       => true,
            ]
        ]);
        $sock = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$sock) return ['tlsVersion'=>null, 'cert'=>null, 'strictTls'=>false];

        $params = stream_context_get_params($sock);
        $tlsVersion = $this->detectTlsVersion($sock);
        $cert = null;
        if (isset($params['options']['ssl']['peer_certificate'])) {
            $res = $params['options']['ssl']['peer_certificate'];
            $parsed = openssl_x509_parse($res, true);
            $cert = [
                'cn'        => $parsed['subject']['CN'] ?? null,
                'issuer'    => $parsed['issuer']['CN'] ?? null,
                'notBefore' => isset($parsed['validFrom_time_t']) ? date('c', (int)$parsed['validFrom_time_t']) : null,
                'notAfter'  => isset($parsed['validTo_time_t']) ? date('c', (int)$parsed['validTo_time_t']) : null,
                'san'       => $this->extractSan($parsed),
            ];
        }
        fclose($sock);

        $strict = in_array($tlsVersion, ['TLSv1.2','TLSv1.3'], true)
               && isset($cert['notAfter']) && strtotime((string)$cert['notAfter']) > time();

        return ['tlsVersion'=>$tlsVersion, 'cert'=>$cert, 'strictTls'=>$strict];
    }

    private function detectTlsVersion($stream): ?string
    {
        $meta = stream_get_meta_data($stream);
        $wr   = (string)($meta['wrapper_data'][0] ?? '');
        if (stripos($wr, 'TLSv1.3') !== false) return 'TLSv1.3';
        if (stripos($wr, 'TLSv1.2') !== false) return 'TLSv1.2';
        if (stripos($wr, 'TLSv1.1') !== false) return 'TLSv1.1';
        if (stripos($wr, 'TLSv1')   !== false) return 'TLSv1.0';
        return null;
    }

    /** @return string[] */
    private function extractSan(array $parsed): array
    {
        $san = (string)($parsed['extensions']['subjectAltName'] ?? '');
        $out = [];
        foreach (explode(',', $san) as $e) {
            $e = trim($e);
            if (stripos($e, 'DNS:') === 0) $out[] = trim(substr($e, 4));
        }
        return $out;
    }
}
