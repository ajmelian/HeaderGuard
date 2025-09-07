<?php
/** @var string $url */
/** @var array $report */
/** @var string|null $aiText */
/** @var array{ok:bool,blocks:int,firstTs:?int,lastTs:?int} $ledgerStatus */
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>HeaderGuard • Resultado</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>.badge-k{font-size:.9rem}</style>
</head>
<body class="bg-light">
<div class="container py-4">
  <a href="./" class="btn btn-link">← Nuevo análisis</a>
  <h1 class="mt-2 mb-3">Resultado</h1>

  <div class="card mb-3">
    <div class="card-body">
      <h5 class="card-title"><?= htmlspecialchars($url, ENT_QUOTES, 'UTF-8') ?></h5>
      <p class="mb-1">HTTP: <strong><?= (int)$report['status'] ?></strong> · Final URL: <code><?= htmlspecialchars($report['finalUrl'], ENT_QUOTES, 'UTF-8') ?></code></p>
      <p class="mb-1">TLS:
        <strong><?= htmlspecialchars($report['tls']['tlsVersion'] ?? 'N/A', ENT_QUOTES, 'UTF-8') ?></strong>
        <?php if (!empty($report['tls']['cert'])): $c=$report['tls']['cert']; ?>
          · CN: <code><?= htmlspecialchars($c['cn'] ?? '', ENT_QUOTES, 'UTF-8') ?></code>
          · Issuer: <code><?= htmlspecialchars($c['issuer'] ?? '', ENT_QUOTES, 'UTF-8') ?></code>
          · Validez hasta: <code><?= htmlspecialchars($c['notAfter'] ?? '', ENT_QUOTES, 'UTF-8') ?></code>
        <?php endif; ?>
      </p>
      <div class="display-6">Score: <?= (int)$report['score'] ?>/100</div>
    </div>
  </div>

  <div class="row g-3">
    <div class="col-md-6">
      <div class="card h-100">
        <div class="card-header">Cabeceras presentes</div>
        <div class="card-body">
          <?php foreach ($report['present'] as $k): ?>
            <span class="badge text-bg-success badge-k"><?= htmlspecialchars($k, ENT_QUOTES, 'UTF-8') ?></span>
          <?php endforeach; ?>
          <?php if (empty($report['present'])): ?><p class="text-muted">Ninguna clave detectada.</p><?php endif; ?>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card h-100">
        <div class="card-header">Cabeceras faltantes</div>
        <div class="card-body">
          <?php foreach ($report['missing'] as $k): ?>
            <span class="badge text-bg-danger badge-k"><?= htmlspecialchars($k, ENT_QUOTES, 'UTF-8') ?></span>
          <?php endforeach; ?>
          <?php if (empty($report['missing'])): ?><p class="text-muted">¡Perfecto!</p><?php endif; ?>
        </div>
      </div>
    </div>
  </div>

  <?php if (!empty($report['advise'])): ?>
  <div class="card my-3">
    <div class="card-header">Recomendaciones</div>
    <div class="card-body">
      <ul class="mb-0">
        <?php foreach ($report['advise'] as $a): ?>
          <li><code><?= htmlspecialchars($a, ENT_QUOTES, 'UTF-8') ?></code></li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>
  <?php endif; ?>

  <?php if (!empty($aiText)): ?>
  <div class="card my-3 border-primary">
    <div class="card-header bg-primary text-white">Explicación IA</div>
    <div class="card-body"><pre class="mb-0" style="white-space:pre-wrap"><?= htmlspecialchars($aiText, ENT_QUOTES, 'UTF-8') ?></pre></div>
  </div>
  <?php endif; ?>

  <div class="card my-3">
    <div class="card-header">Ledger .DAT</div>
    <div class="card-body">
      <small class="text-muted">
        Cadena verificada:
        <strong class="<?= !empty($ledgerStatus['ok']) ? 'text-success' : 'text-danger' ?>">
          <?= !empty($ledgerStatus['ok']) ? 'OK' : 'ERROR' ?>
        </strong>
        — Bloques: <?= (int)$ledgerStatus['blocks'] ?>
      </small>
    </div>
  </div>

  <div class="accordion my-3" id="accRaw">
    <div class="accordion-item">
      <h2 class="accordion-header"><button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#raw">Ver cabeceras crudas</button></h2>
      <div id="raw" class="accordion-collapse collapse"><div class="accordion-body">
        <pre class="mb-0"><?php foreach ($report['headers'] as $k=>$v) echo htmlspecialchars($k.': '.$v, ENT_QUOTES, 'UTF-8')."\n"; ?></pre>
      </div></div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
