<?php
declare(strict_types=1);

/**
 * Nombre: AiClient
 * Descripción:
 *   Cliente mínimo para OpenAI/Claude. Sanea PII básica en el prompt y devuelve texto.
 * Entradas:
 *   - string $provider ('openai'|'claude'), string $apiKey
 * Salida:
 *   - string Texto generado
 * Método de uso:
 *   - $ai = new AiClient('openai',$key); $txt = $ai->complete('...', 'gpt-4o-mini', 350);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class AiClient
{
    public function __construct(private string $provider, private string $apiKey) {}

    public function complete(string $prompt, string $model, int $maxTokens = 300): string
    {
        $prompt = $this->sanitize($prompt);
        $url = $this->provider === 'claude' ? 'https://api.anthropic.com/v1/messages' : 'https://api.openai.com/v1/chat/completions';
        $payload = $this->provider === 'claude'
            ? ['model'=>$model,'max_tokens'=>$maxTokens,'messages'=>[['role'=>'user','content'=>$prompt]]]
            : ['model'=>$model,'messages'=>[['role'=>'user','content'=>$prompt]],'max_tokens'=>$maxTokens];

        $ch = curl_init($url);
        $headers = $this->provider === 'claude'
            ? ['x-api-key: '.$this->apiKey,'anthropic-version: 2023-06-01','content-type: application/json']
            : ['authorization: Bearer '.$this->apiKey,'content-type: application/json'];

        curl_setopt_array($ch, [
            CURLOPT_POST=>true, CURLOPT_HTTPHEADER=>$headers,
            CURLOPT_POSTFIELDS=>json_encode($payload, JSON_THROW_ON_ERROR),
            CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) throw new RuntimeException('Error IA: '.curl_error($ch));
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($code >= 300) throw new RuntimeException('IA respondió código '.$code);
        $data = json_decode($resp, true);
        return $this->provider === 'claude'
            ? (string)($data['content'][0]['text'] ?? '')
            : (string)($data['choices'][0]['message']['content'] ?? '');
    }

    private function sanitize(string $t): string
    {
        $t = preg_replace('/\b\d{8}[A-HJ-NP-TV-Z]\b/u', '[[PII:NIF]]', $t) ?? $t;
        $t = preg_replace('/\b[XYZ]\d{7}[A-Z]\b/u', '[[PII:NIE]]', $t) ?? $t;
        $t = preg_replace('/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/iu', '[[PII:EMAIL]]', $t) ?? $t;
        $t = preg_replace('/\b\+?\d{2,3}[\s\-]?\d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b/u', '[[PII:PHONE]]', $t) ?? $t;
        return $t;
    }
}
