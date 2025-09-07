<?php
declare(strict_types=1);

/**
 * Nombre: TrustChainDat
 * Descripción:
 *   Ledger apéndice-solo en .DAT con encadenado por hash (prevHash) y raíz de Merkle por lote.
 *   Firma HMAC cada cabecera de bloque (integridad). "Transparency Log" sencillo.
 * Entradas:
 *   - string $datPath, string $hmacKey
 * Salida:
 *   - appendBlock(array $txHashes): BlockHeader
 *   - verifyChain(): array{ok:bool,blocks:int,firstTs:?int,lastTs:?int}
 * Método de uso:
 *   - $hdr = (new TrustChainDat($path,$key))->appendBlock([$shaTx]);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class TrustChainDat
{
    public function __construct(private string $datPath, private string $hmacKey) {}

    /** @param string[] $txHashes */
    public function appendBlock(array $txHashes): BlockHeader
    {
        $txHashes = array_values(array_filter(array_map('strtolower', $txHashes), fn($h) => preg_match('/^[0-9a-f]{64}$/', $h)));
        if (!$txHashes) throw new RuntimeException('Se requieren hashes sha256 válidos.');

        $merkle = new MerkleTree($txHashes);
        $root   = $merkle->getRoot();

        $last = $this->getLastHeader();
        $hdr  = new BlockHeader(
            index: ($last?->index ?? 0) + 1,
            timestamp: time(),
            prevHash: $last?->hash() ?? str_repeat('0', 64),
            merkleRoot: $root
        );
        $sig = $hdr->sign($this->hmacKey);

        if (!is_dir(dirname($this->datPath))) mkdir(dirname($this->datPath), 0750, true);
        file_put_contents($this->datPath, $hdr->toJson()."\t".$sig.PHP_EOL, FILE_APPEND|LOCK_EX);

        return $hdr;
    }

    public function getLastHeader(): ?BlockHeader
    {
        if (!is_file($this->datPath) || filesize($this->datPath) === 0) return null;
        $fh = fopen($this->datPath, 'rb');
        fseek($fh, -4096, SEEK_END);
        $tail = stream_get_contents($fh) ?: '';
        fclose($fh);
        $lines = array_values(array_filter(explode("\n", $tail)));
        $last  = $lines[count($lines)-1] ?? '';
        if ($last === '') return null;

        [$json, $sig] = array_pad(explode("\t", $last), 2, '');
        $arr = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $hdr = new BlockHeader($arr['index'], $arr['timestamp'], $arr['prevHash'], $arr['merkleRoot']);
        if (!$hdr->verify($this->hmacKey, $sig)) {
            throw new RuntimeException('Firma HMAC inválida en el último bloque.');
        }
        return $hdr;
    }

    /** @return array{ok:bool,blocks:int,firstTs:?int,lastTs:?int} */
    public function verifyChain(): array
    {
        if (!is_file($this->datPath)) return ['ok'=>true,'blocks'=>0,'firstTs'=>null,'lastTs'=>null];

        $fh = fopen($this->datPath, 'rb');
        $prevHash = str_repeat('0', 64);
        $count = 0; $firstTs = null; $lastTs = null;

        while (($line = fgets($fh)) !== false) {
            [$json, $sig] = array_pad(explode("\t", trim($line)), 2, '');
            $arr = json_decode($json, true);
            $hdr = new BlockHeader($arr['index'], $arr['timestamp'], $arr['prevHash'], $arr['merkleRoot']);
            if (!$hdr->verify($this->hmacKey, $sig) || $hdr->prevHash !== $prevHash) {
                fclose($fh);
                return ['ok'=>false,'blocks'=>$count,'firstTs'=>$firstTs,'lastTs'=>$lastTs];
            }
            $prevHash = $hdr->hash();
            $firstTs ??= $hdr->timestamp;
            $lastTs = $hdr->timestamp;
            $count++;
        }
        fclose($fh);
        return ['ok'=>true,'blocks'=>$count,'firstTs'=>$firstTs,'lastTs'=>$lastTs];
    }
}

/**
 * Nombre: BlockHeader
 * Descripción: Cabecera de bloque (index, timestamp, prevHash, merkleRoot) con firma HMAC.
 * Entradas: ver constructor.
 * Salida: hash(), toJson(), sign(), verify().
 * Método de uso: $hdr = new BlockHeader(...); $hdr->sign($key);
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class BlockHeader
{
    public function __construct(
        public int $index,
        public int $timestamp,
        public string $prevHash,
        public string $merkleRoot
    ) {}

    public function toJson(): string
    {
        return json_encode([
            'index'      => $this->index,
            'timestamp'  => $this->timestamp,
            'prevHash'   => strtolower($this->prevHash),
            'merkleRoot' => strtolower($this->merkleRoot)
        ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    }

    public function hash(): string
    {
        return hash('sha256', $this->toJson());
    }

    public function sign(string $hmacKey): string
    {
        return hash_hmac('sha256', $this->toJson(), $hmacKey);
    }

    public function verify(string $hmacKey, string $signature): bool
    {
        return hash_equals($this->sign($hmacKey), $signature);
    }
}

/**
 * Nombre: MerkleTree
 * Descripción: Cálculo de raíz de Merkle a partir de hojas sha256 (hex).
 * Entradas: string[] $leaves
 * Salida: getRoot(): string
 * Método de uso: $root = (new MerkleTree($leaves))->getRoot();
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */
final class MerkleTree
{
    /** @var string[][] */
    private array $levels = [];

    /** @param string[] $leaves */
    public function __construct(array $leaves)
    {
        $leaves = array_values(array_filter(array_map('strtolower', $leaves), fn($h) => preg_match('/^[0-9a-f]{64}$/', $h)));
        if (!$leaves) throw new RuntimeException('Hojas de Merkle inválidas.');
        $this->build($leaves);
    }

    public function getRoot(): string { return $this->levels[0][0]; }

    /** @param string[] $leaves */
    private function build(array $leaves): void
    {
        $level = array_values($leaves);
        $this->levels = []; $this->levels[] = $level;
        while (count($level) > 1) {
            $next = [];
            for ($i=0; $i<count($level); $i+=2) {
                $a = $level[$i]; $b = $level[$i+1] ?? $a;
                $next[] = hash('sha256', hex2bin($a).hex2bin($b));
            }
            $level = $next;
            $this->levels[] = $level;
        }
        $this->levels = array_reverse($this->levels);
    }
}
