<?php
declare(strict_types=1);

/**
 * Nombre: HttpHeadersFetcher
 * Descripción:
 *   Obtiene cabeceras HTTP y metadatos usando cURL (HEAD con fallback a GET).
 * Parámetros de entrada:
 *   - string $url http(s)
 * Salida:
 *   - array{status:int, headers:array<string,string>, finalUrl:string}
 * Método de uso:
 *   - $r = (new HttpHeadersFetcher())->fetchHeadAndHeaders($url);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class HttpHeadersFetcher
{
    /** @return array{status:int, headers:array<string,string>, finalUrl:string} */
    public function fetchHeadAndHeaders(string $url): array
    {
        $r = $this->curlRequest($url, true);
        if ($r['status'] === 405 || empty($r['headers'])) {
            $r = $this->curlRequest($url, false);
        }
        return $r;
    }

    /** @return array{status:int, headers:array<string,string>, finalUrl:string} */
    private function curlRequest(string $url, bool $head): array
    {
        $headers = [];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY         => $head,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_USERAGENT      => 'HeaderGuard/1.0',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADERFUNCTION => static function($ch, $line) use (&$headers) {
                $trim = trim($line);
                if ($trim === '' || str_starts_with(strtolower($trim), 'http/')) return strlen($line);
                $pos = strpos($trim, ':');
                if ($pos !== false) {
                    $k = strtolower(trim(substr($trim, 0, $pos)));
                    $v = trim(substr($trim, $pos+1));
                    $headers[$k] = $v;
                }
                return strlen($line);
            }
        ]);
        $out = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        if ($out === false && $status === 0) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('Error cURL: '.$err);
        }
        curl_close($ch);
        return ['status'=>$status, 'headers'=>$headers, 'finalUrl'=>$finalUrl ?: $url];
    }
}
