<?php
/** @var string $csrfToken */
/** @var array{url:string,useAi:bool,aiToken:string,consent:bool} $prefill */
/** @var array $errors */
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>HeaderGuard • Auditoría de Security Headers</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  .error { color:#b00020; font-size:.95rem; }
  .hidden { display:none; }
</style>
</head>
<body class="bg-light">
<div class="container py-5">
  <h1 class="mb-3">HeaderGuard</h1>
  <p class="text-muted">Audita cabeceras HTTP de seguridad y TLS (quick check). IA opcional (ClaudeAI/ChatGPT).</p>

  <?php if (!empty($errors['fatal'])): ?>
    <div class="alert alert-danger"><?= htmlspecialchars($errors['fatal'], ENT_QUOTES, 'UTF-8') ?></div>
  <?php endif; ?>

  <form id="scanForm" class="row g-3" method="post" action="">
    <input type="hidden" name="csrfToken" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">

    <div class="col-12">
      <label class="form-label">URL a analizar</label>
      <input
        type="url"
        name="url"
        required
        class="form-control <?= isset($errors['url']) ? 'is-invalid' : '' ?>"
        placeholder="https://ejemplo.com"
        value="<?= htmlspecialchars($prefill['url'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
        pattern="^https?:\/\/[A-Za-z0-9\-\._~%]+(?::\d{2,5})?(?:\/[^\s]*)?$"
      >
      <?php if (isset($errors['url'])): ?>
        <div class="error"><?= htmlspecialchars($errors['url'], ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>
    </div>

    <div class="col-12">
      <div class="form-check">
        <input class="form-check-input" type="checkbox" id="useAi" name="useAi" <?= !empty($prefill['useAi']) ? 'checked' : '' ?>>
        <label class="form-check-label" for="useAi">Usar IA (ClaudeAI / ChatGPT)</label>
      </div>
    </div>

    <div id="aiTokenWrap" class="col-12 <?= !empty($prefill['useAi']) ? '' : 'hidden' ?>">
      <label class="form-label">Token API (Claude: <code>sk-ant-...</code> · OpenAI: <code>sk-...</code>)</label>
      <input
        type="text"
        name="aiToken"
        class="form-control <?= isset($errors['aiToken']) ? 'is-invalid' : '' ?>"
        placeholder="sk-..."
        value="<?= htmlspecialchars($prefill['aiToken'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
      >
      <?php if (isset($errors['aiToken'])): ?>
        <div class="error"><?= htmlspecialchars($errors['aiToken'], ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>
    </div>

    <div class="col-12">
      <div class="border rounded p-3 bg-white">
        <h6>Datos que recogemos y procesamos</h6>
        <ul class="mb-2">
          <li>La URL introducida y el estado HTTP.</li>
          <li>Cabeceras devueltas por el servidor y metadatos TLS (CN, emisor, validez, versión TLS).</li>
          <li>Hash de un resumen técnico (score, cabeceras faltantes, estricto TLS) anclado en un ledger <code>.DAT</code> (no almacenamos la URL en el ledger, solo el <em>hash</em>).</li>
          <li>Si activas IA, enviamos un resumen técnico a la API seleccionada (Claude/OpenAI). No guardamos tu token.</li>
          <li>Registramos un log con <em>ipHash</em>, user-agent, fecha/hora UTC, URL y resultado, así como si se ha usado IA.</li>
        </ul>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="consent" name="consent" <?= !empty($prefill['consent']) ? 'checked' : '' ?>>
          <label class="form-check-label" for="consent">He leído y acepto el tratamiento de datos descrito.</label>
        </div>
        <?php if (isset($errors['consent'])): ?>
          <div class="error mt-1"><?= htmlspecialchars($errors['consent'], ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
      </div>
    </div>

    <div class="col-12">
      <button id="submitBtn" class="btn btn-primary" type="submit" <?= !empty($prefill['consent']) ? '' : 'disabled' ?>>Procesar</button>
    </div>
  </form>
</div>

<script>
(function(){
  const useAi = document.getElementById('useAi');
  const aiWrap = document.getElementById('aiTokenWrap');
  const consent = document.getElementById('consent');
  const submitBtn = document.getElementById('submitBtn');

  function toggleAi(){
    aiWrap.classList.toggle('hidden', !useAi.checked);
  }
  function toggleSubmit(){
    submitBtn.disabled = !consent.checked;
  }

  useAi.addEventListener('change', toggleAi);
  consent.addEventListener('change', toggleSubmit);
  toggleAi(); toggleSubmit();
})();
</script>
</body>
</html>
