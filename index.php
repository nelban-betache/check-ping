<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NetCheck Diagnostic Tool</title>

  <style>
    /* Basic variables */
    :root{
      --bg: #f5f7fb;
      --card: #ffffff;
      --muted: #6b7280;
      --accent: #2563eb;
      --danger: #dc2626;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", "Courier New", monospace;
      --radius: 12px;
      --gap: 1rem;
      --max-width: 880px;
    }

    /* Reset-ish */
    *{box-sizing: border-box}
    html,body{height:100%}
    body{
      margin:0;
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      background: linear-gradient(180deg, var(--bg), #eef2ff 120%);
      color:#0f172a;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
      padding:2rem;
      display:flex;
      align-items:flex-start;
      justify-content:center;
    }

    /* Page container */
    .wrap{
      width:100%;
      max-width:var(--max-width);
      background:var(--card);
      border-radius:var(--radius);
      padding:1.25rem;
      box-shadow: 0 6px 20px rgba(16,24,40,0.06);
      border: 1px solid rgba(15,23,42,0.04);
    }

    header{
      display:flex;
      gap:.75rem;
      align-items:center;
      margin-bottom:.75rem;
    }
    header h1{
      font-size:1.125rem;
      margin:0;
      line-height:1;
    }
    header p{
      margin:0;
      color:var(--muted);
      font-size:.9rem;
    }

    /* Form layout - mobile first */
    form{
      display:grid;
      grid-template-columns: 1fr auto;
      gap: .5rem;
      align-items:center;
      margin: .75rem 0 1rem 0;
    }

    label{
      display:none; /* we keep the input placeholder for compact UI, but accessible label kept in markup */
    }

    input[type="text"]{
      padding: .65rem .75rem;
      border-radius: 10px;
      border:1px solid rgba(15,23,42,0.08);
      font-size:1rem;
      outline:none;
      transition:box-shadow .12s ease, border-color .12s ease;
      width:100%;
      background:linear-gradient(180deg,#fff,#fbfdff);
    }
    input[type="text"]:focus{
      box-shadow: 0 4px 14px rgba(37,99,235,0.07);
      border-color: rgba(37,99,235,0.45);
    }

    button, input[type="submit"]{
      appearance:none;
      border:0;
      background:var(--accent);
      color:white;
      padding: .65rem .95rem;
      font-weight:600;
      border-radius:10px;
      cursor:pointer;
      font-size:1rem;
      min-width:84px;
      box-shadow: 0 6px 18px rgba(37,99,235,0.12);
      transition: transform .08s ease, box-shadow .08s ease, opacity .08s ease;
    }
    button:active, input[type="submit"]:active{ transform: translateY(1px) }
    button[disabled]{ opacity:.6; cursor:not-allowed; box-shadow:none }

    /* Extra info area */
    .info{
      color:var(--muted);
      font-size:.9rem;
      margin-bottom: .75rem;
    }

    /* Output area */
    pre{
      margin:0;
      padding:1rem;
      background:#0b1220;
      color:#e6eef8;
      border-radius:10px;
      overflow:auto;
      max-height:48vh; /* keeps output usable on small screens */
      white-space: pre-wrap; /* wrap long lines on narrow screens */
      word-break: break-word;
      font-family: var(--mono);
      font-size: .92rem;
      line-height:1.35;
      border: 1px solid rgba(255,255,255,0.03);
    }

    /* small helper text under the input */
    .hint{
      font-size:.78rem;
      color:var(--muted);
      margin-top:.5rem;
    }

    /* Responsive tweaks for wider screens */
    @media (min-width:640px){
      header h1{ font-size: 1.25rem }
      form{ grid-template-columns: 1fr 160px; gap: .75rem }
      pre{ font-size:0.95rem }
    }

    @media (min-width:960px){
      body{ padding:3rem }
      .wrap{ padding:1.5rem }
      pre{ max-height:60vh }
    }

    /* Accessibility contrast alt (prefers-reduced-motion) */
    @media (prefers-reduced-motion: reduce){
      *{ transition:none !important }
    }
  </style>
</head>
<body>
  <div class="wrap" role="main">
    <header>
      <div>
        <h1>NetCheck Diagnostic Tool</h1>
        <p class="info">Quickly test server availability. Works on phones, tablets and desktops.</p>
      </div>
    </header>

    <!-- Accessible label still present for screen readers -->
    <form method="GET" aria-label="Ping form">
      <!-- visible placeholder keeps UI tidy -->
      <label for="ip">Enter IP Address</label>
      <input id="ip" type="text" name="ip" placeholder="Enter IP address or hostname (e.g. 8.8.8.8 or example.com)" autocomplete="off" inputmode="text" />
      <input type="submit" value="Ping!" />
    </form>

    <p class="hint">Tip: on small screens the output is scrollable — rotate to landscape for wider output.</p>

    <pre>
<?php
if (isset($_GET['ip']) && trim($_GET['ip']) !== '') {
    $target = $_GET['ip'];

    // SECURITY IMPROVEMENT:
    // Use escapeshellarg() to make the input safe for passing to a shell command.
    // This mitigates command injection by properly quoting/escaping the value.
    // Note: for production you should also validate format (IP/hostname) and apply timeouts.
    $safe = escapeshellarg($target);

    // On some systems ping needs different flags (Windows uses -n),
    // this example uses a Unix-like `ping -c 3`.
    $result = shell_exec('ping -c 3 ' . $safe . ' 2>&1');

    // If nothing returned, show a friendly message
    if (!$result) {
        echo "No response or command failed. Ensure the server is reachable and the server allows outgoing ping (ICMP).\n";
    } else {
        echo htmlspecialchars($result, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
?>
    </pre>
  </div>
</body>
</html>
