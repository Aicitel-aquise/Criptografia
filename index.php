<?php
declare(strict_types=1);

session_start();

$localConfigPath = __DIR__ . DIRECTORY_SEPARATOR . '.env';
if (is_file($localConfigPath)) {
    $localConfigLines = file($localConfigPath, FILE_IGNORE_NEW_LINES);

    if ($localConfigLines === false) {
        throw new RuntimeException('No se pudo leer el archivo de configuración local.');
    }

    foreach ($localConfigLines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) {
            continue;
        }

        [$name, $value] = explode('=', $line, 2);
        $name = trim($name);

        if (!preg_match('/^CRYPTOLAB_DB_(HOST|PORT|NAME|USER|PASS)$/', $name)) {
            continue;
        }

        $value = trim($value);
        if (strlen($value) >= 2 && (($value[0] === '"' && $value[-1] === '"') || ($value[0] === "'" && $value[-1] === "'"))) {
            $value = substr($value, 1, -1);
        }

        if (getenv($name) === false) {
            putenv($name . '=' . $value);
        }
    }
}

$dbHost = getenv('CRYPTOLAB_DB_HOST') ?: '127.0.0.1';
$dbPort = getenv('CRYPTOLAB_DB_PORT') ?: '3306';
$dbName = getenv('CRYPTOLAB_DB_NAME') ?: 'cryptonetdb';
$dbUser = getenv('CRYPTOLAB_DB_USER') ?: 'root';
$dbPass = getenv('CRYPTOLAB_DB_PASS');
if ($dbPass === false) {
    $dbPass = '';
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function getCharacters(string $text): array
{
    $characters = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);

    if ($characters === false) {
        throw new InvalidArgumentException('El texto debe tener una codificación UTF-8 válida.');
    }

    return $characters;
}

function caesarCipher(string $text, int $shift): string
{
    $result = '';

    foreach (getCharacters($text) as $character) {
        $code = strlen($character) === 1 ? ord($character) : 0;

        if ($code >= 65 && $code <= 90) {
            $result .= chr(65 + (($code - 65 + $shift) % 26));
        } elseif ($code >= 97 && $code <= 122) {
            $result .= chr(97 + (($code - 97 + $shift) % 26));
        } else {
            $result .= $character;
        }
    }

    return $result;
}

function scytaleCipher(string $text, int $columns, bool $decrypt): string
{
    $characters = getCharacters($text);
    $length = count($characters);

    if ($length === 0) {
        return '';
    }

    $rows = (int) ceil($length / $columns);

    if (!$decrypt) {
        $result = '';
        for ($column = 0; $column < $columns; $column++) {
            for ($row = 0; $row < $rows; $row++) {
                $index = ($row * $columns) + $column;
                if ($index < $length) {
                    $result .= $characters[$index];
                }
            }
        }

        return $result;
    }

    $remainder = $length % $columns;
    $columnsData = [];
    $offset = 0;

    for ($column = 0; $column < $columns; $column++) {
        $columnLength = $rows - ($remainder > 0 && $column >= $remainder ? 1 : 0);
        $columnsData[$column] = array_slice($characters, $offset, $columnLength);
        $offset += $columnLength;
    }

    $result = '';
    for ($row = 0; $row < $rows; $row++) {
        for ($column = 0; $column < $columns; $column++) {
            if (isset($columnsData[$column][$row])) {
                $result .= $columnsData[$column][$row];
            }
        }
    }

    return $result;
}

function frequencyAnalysis(string $text): string
{
    $counts = [];
    $total = 0;
    $uppercaseMap = [
        'á' => 'Á', 'é' => 'É', 'í' => 'Í', 'ó' => 'Ó', 'ú' => 'Ú', 'ü' => 'Ü', 'ñ' => 'Ñ',
    ];

    foreach (getCharacters($text) as $character) {
        if (preg_match('/^\p{L}$/u', $character) !== 1) {
            continue;
        }

        $letter = strtoupper(strtr($character, $uppercaseMap));
        $counts[$letter] = ($counts[$letter] ?? 0) + 1;
        $total++;
    }

    if ($total === 0) {
        return 'No se encontraron letras para analizar.';
    }

    uksort($counts, static function (string $left, string $right) use ($counts): int {
        $byCount = $counts[$right] <=> $counts[$left];
        return $byCount !== 0 ? $byCount : strcmp($left, $right);
    });

    $lines = ['Letra    Apariciones    Frecuencia'];
    foreach ($counts as $letter => $count) {
        $percentage = number_format(($count / $total) * 100, 2, ',', '.');
        $lines[] = sprintf("%-8s %-14d %s%%", $letter, $count, $percentage);
    }
    $lines[] = sprintf('Total de letras analizadas: %d', $total);

    return implode("\n", $lines);
}

function encryptOrAnalyze(string $algorithm, string $operation, string $text, ?int $key): string
{
    if ($algorithm === 'caesar') {
        $shift = $key ?? 0;
        if ($operation === 'Descifrar') {
            $shift = (26 - ($shift % 26)) % 26;
        }

        return caesarCipher($text, $shift);
    }

    if ($algorithm === 'scytale') {
        return scytaleCipher($text, $key ?? 2, $operation === 'Descifrar');
    }

    return frequencyAnalysis($text);
}

$pdo = null;
$databaseError = '';

try {
    if (!preg_match('/^[A-Za-z0-9_]+$/', $dbName)) {
        throw new RuntimeException('El nombre de la base de datos solo puede contener letras, números y guion bajo.');
    }

    $serverDsn = sprintf('mysql:host=%s;port=%s;charset=utf8mb4', $dbHost, $dbPort);
    $server = new PDO($serverDsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $server->exec('CREATE DATABASE IF NOT EXISTS `' . $dbName . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');

    $databaseDsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        $dbHost,
        $dbPort,
        $dbName
    );
    $pdo = new PDO($databaseDsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS historial_criptografia (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            algoritmo VARCHAR(40) NOT NULL,
            operacion VARCHAR(20) NOT NULL,
            texto_original LONGTEXT NOT NULL,
            texto_resultado LONGTEXT NOT NULL,
            clave VARCHAR(100) NULL,
            fecha_operacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
} catch (PDOException | RuntimeException $exception) {
    $databaseError = $exception->getMessage();
}

if (empty($_SESSION['crypto_csrf'])) {
    $_SESSION['crypto_csrf'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $flash = ['type' => 'error', 'message' => '', 'input' => []];
    $postedToken = isset($_POST['csrf']) && is_string($_POST['csrf']) ? $_POST['csrf'] : '';
    $algorithm = isset($_POST['algorithm']) && is_string($_POST['algorithm']) ? $_POST['algorithm'] : '';
    $operation = isset($_POST['operation']) && is_string($_POST['operation']) ? $_POST['operation'] : '';
    $text = isset($_POST['text']) && is_string($_POST['text']) ? $_POST['text'] : '';
    $rawKey = isset($_POST['key']) && is_string($_POST['key']) ? $_POST['key'] : '';

    $flash['input'] = [
        'algorithm' => $algorithm,
        'operation' => $operation,
        'text' => $text,
        'key' => $rawKey,
    ];

    if (!hash_equals($_SESSION['crypto_csrf'], $postedToken)) {
        $flash['message'] = 'La sesión del formulario venció. Actualiza la página e inténtalo nuevamente.';
    } elseif (!in_array($algorithm, ['scytale', 'caesar', 'alkindi'], true)) {
        $flash['message'] = 'Selecciona un algoritmo válido.';
    } elseif (!in_array($operation, ['Cifrar', 'Descifrar', 'Analizar'], true)) {
        $flash['message'] = 'Selecciona una operación válida.';
    } elseif (trim($text) === '') {
        $flash['message'] = 'Escribe un texto para continuar.';
    } elseif (preg_match('//u', $text) !== 1) {
        $flash['message'] = 'El texto debe tener una codificación UTF-8 válida.';
    } elseif (count(getCharacters($text)) > 5000) {
        $flash['message'] = 'El texto no puede superar los 5.000 caracteres.';
    } elseif ($algorithm === 'alkindi' && $operation !== 'Analizar') {
        $flash['message'] = 'El análisis de Al-Kindi solo permite la operación “Analizar”.';
    } elseif ($algorithm !== 'alkindi' && $operation === 'Analizar') {
        $flash['message'] = 'La operación “Analizar” corresponde al algoritmo de Al-Kindi.';
    } elseif ($algorithm !== 'alkindi' && !preg_match('/^-?\d+$/', $rawKey)) {
        $flash['message'] = 'Ingresa una clave numérica válida.';
    } elseif ($algorithm === 'caesar' && ((int) $rawKey < 0 || (int) $rawKey > 25)) {
        $flash['message'] = 'La clave de César debe estar entre 0 y 25.';
    } elseif ($algorithm === 'scytale' && ((int) $rawKey < 2 || (int) $rawKey > 50)) {
        $flash['message'] = 'La clave de Escítala debe estar entre 2 y 50 columnas.';
    } else {
        try {
            $key = $algorithm === 'alkindi' ? null : (int) $rawKey;
            $result = encryptOrAnalyze($algorithm, $operation, $text, $key);
            $algorithmName = [
                'scytale' => 'Escítala',
                'caesar' => 'César',
                'alkindi' => 'Al-Kindi',
            ][$algorithm];

            $flash = [
                'type' => 'success',
                'message' => 'Operación completada.',
                'result' => $result,
                'algorithm_name' => $algorithmName,
                'operation' => $operation,
                'input' => $flash['input'],
                'saved' => false,
            ];

            if ($pdo instanceof PDO) {
                $statement = $pdo->prepare(
                    'INSERT INTO historial_criptografia
                        (algoritmo, operacion, texto_original, texto_resultado, clave)
                     VALUES (:algoritmo, :operacion, :original, :resultado, :clave)'
                );
                $statement->execute([
                    ':algoritmo' => $algorithmName,
                    ':operacion' => $operation,
                    ':original' => $text,
                    ':resultado' => $result,
                    ':clave' => $key === null ? null : (string) $key,
                ]);
                $flash['saved'] = true;
            } else {
                $flash['storage_error'] = $databaseError;
            }
        } catch (InvalidArgumentException $exception) {
            $flash['message'] = $exception->getMessage();
        } catch (PDOException $exception) {
            $flash = [
                'type' => 'success',
                'message' => 'El resultado se calculó, pero no se pudo guardar en el historial.',
                'result' => $result ?? '',
                'algorithm_name' => $algorithmName ?? '',
                'operation' => $operation,
                'input' => $flash['input'],
                'saved' => false,
                'storage_error' => $exception->getMessage(),
            ];
        }
    }

    $_SESSION['crypto_flash'] = $flash;
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$flash = $_SESSION['crypto_flash'] ?? null;
unset($_SESSION['crypto_flash']);

$history = [];
if ($pdo instanceof PDO) {
    try {
        $history = $pdo->query(
            'SELECT id, algoritmo, operacion, texto_original, texto_resultado, clave, fecha_operacion
             FROM historial_criptografia
             ORDER BY fecha_operacion DESC, id DESC
             LIMIT 30'
        )->fetchAll();
    } catch (PDOException $exception) {
        $databaseError = $exception->getMessage();
        $pdo = null;
    }
}

$formInput = is_array($flash['input'] ?? null) ? $flash['input'] : [];
$selectedAlgorithm = $formInput['algorithm'] ?? 'scytale';
$selectedOperation = $formInput['operation'] ?? 'Cifrar';
$selectedText = $formInput['text'] ?? '';
$selectedKey = $formInput['key'] ?? '4';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f5f7fb">
    <title>CryptoLab — Historia de la criptografía</title>
    <style>
        :root {
            color-scheme: light;
            --ink: #172b4d;
            --navy: #183d70;
            --blue: #2c9bd7;
            --blue-dark: #1676b7;
            --orange: #e8872c;
            --paper: #f5f7fb;
            --muted: #64748b;
            --line: #e5eaf1;
            --white: #fff;
            --green: #18794e;
            --shadow: 0 18px 55px rgba(27, 55, 93, .09);
        }

        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            margin: 0;
            color: var(--ink);
            background:
                linear-gradient(rgba(63, 135, 193, .055) 1px, transparent 1px),
                linear-gradient(90deg, rgba(63, 135, 193, .055) 1px, transparent 1px),
                var(--paper);
            background-size: 24px 24px;
            font-family: Inter, "Segoe UI", Arial, sans-serif;
            line-height: 1.55;
        }

        a { color: inherit; text-decoration: none; }
        button, input, select, textarea { font: inherit; }
        .container { width: min(1120px, calc(100% - 40px)); margin-inline: auto; }
        .topbar {
            position: sticky;
            z-index: 5;
            top: 0;
            border-bottom: 1px solid rgba(220, 228, 238, .85);
            background: rgba(255, 255, 255, .92);
            backdrop-filter: blur(14px);
        }
        .topbar-inner { height: 72px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }
        .brand { display: flex; align-items: center; gap: 11px; color: var(--navy); font-weight: 800; letter-spacing: -.03em; }
        .brand-mark {
            display: grid;
            width: 40px;
            height: 40px;
            place-items: center;
            border-radius: 13px;
            color: #fff;
            background: linear-gradient(145deg, #24558c, #2c9bd7);
            box-shadow: 0 7px 15px rgba(44, 155, 215, .25);
        }
        .brand-mark svg { width: 22px; height: 22px; }
        .brand small { display: block; color: #7a8aa0; font-size: .65rem; font-weight: 700; letter-spacing: .12em; }
        .nav { display: flex; align-items: center; gap: 28px; color: #50627a; font-size: .9rem; font-weight: 650; }
        .nav a:hover { color: var(--blue-dark); }
        .nav .nav-cta { padding: 10px 16px; border-radius: 10px; color: #fff; background: var(--navy); }

        .hero { position: relative; overflow: hidden; padding: 76px 0 46px; }
        .hero::after {
            position: absolute;
            top: -105px;
            right: -80px;
            width: 410px;
            height: 410px;
            border: 1px solid rgba(44, 155, 215, .14);
            border-radius: 50%;
            box-shadow: 0 0 0 36px rgba(44, 155, 215, .025), 0 0 0 72px rgba(44, 155, 215, .025);
            content: "";
            pointer-events: none;
        }
        .eyebrow { color: var(--orange); font-size: .75rem; font-weight: 800; letter-spacing: .15em; text-transform: uppercase; }
        h1, h2, h3, p { margin-top: 0; }
        h1, h2, .era-title { font-family: Georgia, "Times New Roman", serif; }
        h1 { max-width: 760px; margin: 12px 0 16px; color: var(--navy); font-size: clamp(2.5rem, 6vw, 4.25rem); letter-spacing: -.045em; line-height: 1.07; }
        .hero-copy { max-width: 650px; color: #5b6b82; font-size: 1.08rem; }
        .hero-actions { display: flex; align-items: center; gap: 12px; margin-top: 26px; }
        .button {
            display: inline-flex;
            min-height: 46px;
            align-items: center;
            justify-content: center;
            gap: 9px;
            padding: 0 18px;
            border: 0;
            border-radius: 11px;
            background: var(--navy);
            color: #fff;
            font-weight: 750;
            cursor: pointer;
            transition: transform .18s ease, box-shadow .18s ease, background .18s ease;
        }
        .button:hover { transform: translateY(-2px); background: #102f5a; box-shadow: 0 10px 22px rgba(24, 61, 112, .18); }
        .button svg { width: 17px; height: 17px; }
        .button-secondary { border: 1px solid #dce5ef; background: #fff; color: var(--navy); }
        .button-secondary:hover { background: #f5f9fd; }

        .section-heading { display: flex; align-items: end; justify-content: space-between; gap: 20px; margin-bottom: 25px; }
        .section-heading h2 { margin: 7px 0 0; color: var(--navy); font-size: clamp(1.7rem, 3vw, 2.2rem); letter-spacing: -.025em; }
        .section-heading p { max-width: 450px; margin: 0; color: var(--muted); font-size: .92rem; }
        .timeline-section { padding: 24px 0 70px; }
        .timeline { position: relative; display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .timeline::before {
            position: absolute;
            z-index: 0;
            top: 44px;
            right: 12%;
            left: 12%;
            height: 4px;
            border-radius: 99px;
            background: linear-gradient(90deg, #44a6da, #e99a46);
            content: "";
        }
        .era-card { position: relative; z-index: 1; text-align: center; }
        .era-icon {
            display: grid;
            width: 82px;
            height: 82px;
            place-items: center;
            margin: 4px auto 12px;
            border: 7px solid var(--paper);
            border-radius: 50%;
            background: #fff;
            color: var(--navy);
            box-shadow: 0 5px 20px rgba(27, 55, 93, .12);
            font-size: 2rem;
        }
        .era-icon svg { width: 34px; height: 34px; }
        .era-date { display: inline-flex; min-width: 130px; justify-content: center; padding: 7px 15px; border-radius: 99px; background: var(--navy); color: #fff; font-size: .8rem; font-weight: 750; }
        .era-dot { width: 16px; height: 16px; margin: 3px auto 10px; border-radius: 50%; background: var(--orange); box-shadow: 0 0 0 5px rgba(232, 135, 44, .12); }
        .era-title { margin: 0 0 5px; color: #d9771d; font-size: 1.3rem; }
        .era-card p { max-width: 290px; margin: 0 auto; color: #52647a; font-size: .9rem; }

        .insight {
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 0 auto 78px;
            padding: 16px 21px;
            border: 1px solid #cde2f1;
            border-radius: 14px;
            background: rgba(234, 246, 255, .88);
            color: #33506e;
        }
        .insight-icon { display: grid; width: 38px; height: 38px; flex: 0 0 auto; place-items: center; border-radius: 50%; background: #d3ecfb; color: var(--blue-dark); }
        .insight-icon svg { width: 21px; height: 21px; }
        .insight p { margin: 0; }

        .work-section { padding: 72px 0; background: rgba(235, 241, 248, .72); border-block: 1px solid rgba(220, 228, 238, .8); }
        .work-grid { display: grid; grid-template-columns: minmax(0, 1.02fr) minmax(0, .98fr); gap: 24px; align-items: start; }
        .panel { border: 1px solid #e4eaf1; border-radius: 18px; background: #fff; box-shadow: var(--shadow); }
        .panel-head { padding: 24px 26px 0; }
        .panel-head h2 { margin: 5px 0 6px; color: var(--navy); font-size: 1.65rem; }
        .panel-head p { margin: 0; color: var(--muted); font-size: .9rem; }
        .form-body { display: grid; gap: 17px; padding: 22px 26px 26px; }
        .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .field label { display: block; margin-bottom: 7px; color: #344861; font-size: .85rem; font-weight: 750; }
        .field input, .field select, .field textarea {
            width: 100%;
            border: 1px solid #d9e2ec;
            border-radius: 10px;
            outline: 0;
            background: #fff;
            color: var(--ink);
            transition: border-color .15s, box-shadow .15s;
        }
        .field input, .field select { height: 46px; padding: 0 12px; }
        .field textarea { min-height: 138px; resize: vertical; padding: 12px; line-height: 1.55; }
        .field input:focus, .field select:focus, .field textarea:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(44, 155, 215, .13); }
        .field-hint { display: block; margin-top: 6px; color: #8290a2; font-size: .76rem; }
        .form-body .button { width: 100%; }
        .alert { margin: 0 0 18px; padding: 13px 15px; border: 1px solid; border-radius: 11px; font-size: .88rem; }
        .alert-error { border-color: #f1c8c4; background: #fff5f4; color: #9c3428; }
        .alert-success { border-color: #cce8d9; background: #f2fbf6; color: #286344; }
        .alert-warning { margin-top: 11px; border-color: #f0d7b1; background: #fff9ef; color: #815517; }
        .result-card { min-height: 329px; }
        .result-card .panel-head { display: flex; justify-content: space-between; gap: 12px; }
        .result-content { padding: 22px 26px 26px; }
        .result-placeholder { display: grid; min-height: 215px; place-content: center; justify-items: center; border: 1px dashed #d6e0ea; border-radius: 12px; color: #8290a2; text-align: center; }
        .result-placeholder .placeholder-icon { display: grid; width: 53px; height: 53px; place-items: center; margin-bottom: 12px; border-radius: 16px; background: #edf5fb; color: var(--blue-dark); }
        .result-placeholder svg { width: 25px; height: 25px; }
        .result-placeholder strong { color: #52647a; }
        .result-meta { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 12px; }
        .pill { padding: 5px 9px; border-radius: 99px; background: #eef4fa; color: #38536f; font-size: .75rem; font-weight: 750; }
        .result-box { overflow: auto; min-height: 135px; max-height: 340px; margin: 0; padding: 16px; border: 1px solid #dfe8f0; border-radius: 12px; background: #f8fafc; color: #243f5e; font: .9rem/1.65 "Cascadia Code", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
        .result-actions { display: flex; justify-content: flex-end; margin-top: 12px; }
        .small-button { display: inline-flex; align-items: center; gap: 7px; padding: 8px 11px; border: 1px solid #dce5ef; border-radius: 9px; background: #fff; color: #36506e; font-size: .78rem; font-weight: 750; cursor: pointer; }
        .small-button:hover { background: #f2f7fb; }
        .database-note { display: flex; align-items: center; gap: 8px; margin-top: 17px; color: #65768c; font-size: .78rem; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); }
        .status-dot.offline { background: #c64737; }

        .history-section { padding: 76px 0 86px; }
        .history-panel { overflow: hidden; }
        .history-top { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 23px 26px; border-bottom: 1px solid var(--line); }
        .history-top h2 { margin: 0; color: var(--navy); font-size: 1.65rem; }
        .history-top p { margin: 4px 0 0; color: var(--muted); font-size: .86rem; }
        .db-status { display: inline-flex; align-items: center; gap: 8px; padding: 7px 10px; border-radius: 99px; background: #eef8f1; color: #28714b; font-size: .75rem; font-weight: 750; white-space: nowrap; }
        .db-status.offline { background: #fff2f0; color: #a33e32; }
        .table-scroll { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 13px 17px; border-bottom: 1px solid #edf1f5; vertical-align: top; }
        th { background: #f8fafc; color: #66778d; font-size: .72rem; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; white-space: nowrap; }
        td { color: #40546d; font-size: .84rem; }
        tbody tr:last-child td { border-bottom: 0; }
        .table-text { display: block; max-width: 210px; overflow: hidden; color: #314861; text-overflow: ellipsis; white-space: nowrap; }
        .algo-label { display: inline-flex; padding: 4px 8px; border-radius: 7px; background: #edf5fb; color: #2e5e88; font-size: .76rem; font-weight: 750; }
        .empty-history { padding: 33px 20px; color: #79899c; text-align: center; }
        .empty-history strong { display: block; margin-bottom: 4px; color: #4a6078; }
        footer { padding: 24px 0; border-top: 1px solid #e0e7ef; color: #738399; font-size: .8rem; text-align: center; }
        footer strong { color: var(--navy); }

        @media (max-width: 760px) {
            .nav { gap: 14px; font-size: .82rem; }
            .nav a:not(.nav-cta) { display: none; }
            .hero { padding-top: 56px; }
            .timeline-section { padding-bottom: 55px; }
            .timeline { grid-template-columns: 1fr; gap: 24px; }
            .timeline::before { top: 34px; bottom: 40px; left: 39px; width: 3px; height: auto; background: linear-gradient(180deg, #44a6da, #e99a46); }
            .era-card { display: grid; grid-template-columns: 78px 1fr; grid-template-rows: auto auto auto; column-gap: 13px; align-items: center; text-align: left; }
            .era-icon { grid-column: 1; grid-row: 1 / 4; width: 72px; height: 72px; margin: 0; }
            .era-date { grid-column: 2; grid-row: 1; min-width: 0; justify-self: start; margin-bottom: 4px; }
            .era-dot { display: none; }
            .era-title { grid-column: 2; grid-row: 2; margin-bottom: 2px; }
            .era-card p { grid-column: 2; grid-row: 3; margin: 0; }
            .insight { margin-bottom: 55px; }
            .work-grid { grid-template-columns: 1fr; }
            .section-heading { align-items: start; flex-direction: column; }
            .history-top { align-items: start; flex-direction: column; }
        }
        @media (max-width: 480px) {
            .container { width: min(100% - 28px, 1120px); }
            .topbar-inner { height: 64px; }
            .nav .nav-cta { padding: 9px 11px; }
            .hero { padding: 48px 0 34px; }
            .hero-actions { align-items: stretch; flex-direction: column; }
            .field-row { grid-template-columns: 1fr; gap: 12px; }
            .panel-head, .form-body, .result-content { padding-right: 18px; padding-left: 18px; }
            .panel-head { padding-top: 20px; }
            .result-card .panel-head { display: block; }
            .history-top { padding: 20px 18px; }
            th, td { padding: 12px; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="container topbar-inner">
            <a class="brand" href="#" aria-label="CryptoLab, inicio">
                <span class="brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="8" cy="15" r="4"></circle><path d="m11 12 7-7 3 3-2 2 2 2-3 3-2-2-2 2"></path><path d="M8 15h.01"></path>
                    </svg>
                </span>
                <span><small>LABORATORIO DE</small>CryptoLab</span>
            </a>
            <nav class="nav" aria-label="Navegación principal">
                <a href="#historia">Historia</a>
                <a href="#historial">Historial</a>
                <a class="nav-cta" href="#practica">Probar algoritmos <span aria-hidden="true">→</span></a>
            </nav>
        </div>
    </header>

    <main>
        <section class="hero container">
            <span class="eyebrow">Ingeniería de software · Criptografía</span>
            <h1>Historia de la criptografía</h1>
            <p class="hero-copy">Un viaje por los ingeniosos métodos que protegieron mensajes a través del tiempo. Aprende su historia y pon a prueba los algoritmos clásicos.</p>
            <div class="hero-actions">
                <a class="button" href="#practica">
                    Explorar el laboratorio
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"></path></svg>
                </a>
                <a class="button button-secondary" href="#historia">Conocer la historia</a>
            </div>
        </section>

        <section class="timeline-section container" id="historia" aria-labelledby="history-title">
            <div class="section-heading">
                <div>
                    <span class="eyebrow">Historia del cifrado · Parte 1</span>
                    <h2 id="history-title">Tres ideas que cambiaron la historia</h2>
                </div>
                <p>De una vara de madera a las matemáticas: así evolucionó el arte de mantener secretos.</p>
            </div>
            <div class="timeline">
                <article class="era-card">
                    <div class="era-icon" aria-hidden="true">▤</div>
                    <span class="era-date">Siglo V a. C.</span>
                    <div class="era-dot"></div>
                    <h3 class="era-title">Escítala</h3>
                    <p>Esparta enrollaba una tira en una vara. Solo quien tuviera otra del mismo grosor podía leer el mensaje.</p>
                </article>
                <article class="era-card">
                    <div class="era-icon" aria-hidden="true"><span style="font-family:Georgia,serif;font-weight:800">C</span></div>
                    <span class="era-date">Siglo I a. C.</span>
                    <div class="era-dot"></div>
                    <h3 class="era-title">Cifrado César</h3>
                    <p>Julio César corría cada letra tres lugares en el alfabeto. Una sustitución sencilla, pero ingeniosa.</p>
                </article>
                <article class="era-card">
                    <div class="era-icon" aria-hidden="true">
                        <svg viewBox="0 0 36 36" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="15" cy="15" r="10"></circle><path d="m22.5 22.5 9 9M11 19v-5m4 5V9m4 10v-8"></path>
                        </svg>
                    </div>
                    <span class="era-date">Siglo IX</span>
                    <div class="era-dot"></div>
                    <h3 class="era-title">Al-Kindi</h3>
                    <p>El sabio árabe estudió la frecuencia de las letras y abrió el camino al criptoanálisis estadístico.</p>
                </article>
            </div>
        </section>

        <aside class="insight container">
            <span class="insight-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="8" cy="15" r="4"></circle><path d="m11 12 7-7 3 3-2 2 2 2-3 3-2-2-2 2"></path><path d="M8 15h.01"></path>
                </svg>
            </span>
            <p><strong>¿Qué tienen en común?</strong> En los cifrados clásicos, quien conoce la clave puede transformar el mensaje y recuperar el texto original.</p>
        </aside>

        <section class="work-section" id="practica">
            <div class="container">
                <div class="section-heading">
                    <div>
                        <span class="eyebrow">Aprender haciendo</span>
                        <h2>Laboratorio de cifrado</h2>
                    </div>
                    <p>Elige una técnica, escribe tu mensaje y observa cómo funciona paso a paso.</p>
                </div>
                <div class="work-grid">
                    <section class="panel" aria-labelledby="tool-title">
                        <div class="panel-head">
                            <h2 id="tool-title">Prueba un algoritmo</h2>
                            <p>Los resultados se guardan automáticamente en el historial.</p>
                        </div>
                        <form class="form-body" method="post" action="#practica">
                            <input type="hidden" name="csrf" value="<?= h($_SESSION['crypto_csrf']) ?>">
                            <?php if (isset($flash['type']) && $flash['type'] === 'error'): ?>
                                <div class="alert alert-error" role="alert"><?= h((string) $flash['message']) ?></div>
                            <?php endif; ?>
                            <div class="field-row">
                                <div class="field">
                                    <label for="algorithm">Algoritmo</label>
                                    <select id="algorithm" name="algorithm">
                                        <option value="scytale" <?= $selectedAlgorithm === 'scytale' ? 'selected' : '' ?>>Escítala · Transposición</option>
                                        <option value="caesar" <?= $selectedAlgorithm === 'caesar' ? 'selected' : '' ?>>César · Sustitución</option>
                                        <option value="alkindi" <?= $selectedAlgorithm === 'alkindi' ? 'selected' : '' ?>>Al-Kindi · Frecuencias</option>
                                    </select>
                                </div>
                                <div class="field">
                                    <label for="operation">Operación</label>
                                    <select id="operation" name="operation">
                                        <option value="Cifrar" <?= $selectedOperation === 'Cifrar' ? 'selected' : '' ?>>Cifrar</option>
                                        <option value="Descifrar" <?= $selectedOperation === 'Descifrar' ? 'selected' : '' ?>>Descifrar</option>
                                        <option value="Analizar" <?= $selectedOperation === 'Analizar' ? 'selected' : '' ?>>Analizar frecuencias</option>
                                    </select>
                                </div>
                            </div>
                            <div class="field">
                                <label for="text">Tu mensaje</label>
                                <textarea id="text" name="text" maxlength="5000" placeholder="Escribe aquí el texto que quieres cifrar o analizar..." required><?= h($selectedText) ?></textarea>
                                <span class="field-hint">Hasta 5.000 caracteres. Se conservan espacios y signos.</span>
                            </div>
                            <div class="field" id="key-field">
                                <label for="key" id="key-label">Clave</label>
                                <input id="key" name="key" type="number" min="2" max="50" value="<?= h($selectedKey) ?>" inputmode="numeric">
                                <span class="field-hint" id="key-hint">Número de columnas de la vara (2–50).</span>
                            </div>
                            <button class="button" type="submit">
                                Ejecutar operación
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m8 5 12 7-12 7V5Z"></path></svg>
                            </button>
                        </form>
                    </section>

                    <section class="panel result-card" aria-labelledby="result-title">
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">Tu resultado</span>
                                <h2 id="result-title">Salida del laboratorio</h2>
                                <p>El texto procesado aparecerá aquí.</p>
                            </div>
                        </div>
                        <div class="result-content">
                            <?php if (isset($flash['type']) && $flash['type'] === 'success'): ?>
                                <div class="alert alert-success" role="status">
                                    <?= h((string) $flash['message']) ?>
                                    <?php if (!empty($flash['saved'])): ?> Se registró en el historial.<?php endif; ?>
                                </div>
                                <div class="result-meta">
                                    <span class="pill"><?= h((string) $flash['algorithm_name']) ?></span>
                                    <span class="pill"><?= h((string) $flash['operation']) ?></span>
                                </div>
                                <pre class="result-box" id="result-text"><?= h((string) $flash['result']) ?></pre>
                                <div class="result-actions">
                                    <button class="small-button" id="copy-result" type="button" aria-label="Copiar resultado">
                                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="8" y="8" width="12" height="12" rx="2"></rect><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"></path></svg>
                                        <span>Copiar resultado</span>
                                    </button>
                                </div>
                                <?php if (empty($flash['saved'])): ?>
                                    <div class="alert alert-warning" role="alert">
                                        No se guardó en la base de datos. <?= h((string) ($flash['storage_error'] ?? $databaseError)) ?>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <div class="result-placeholder">
                                    <span class="placeholder-icon" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19V5m0 14h16M8 15v-4m4 4V7m4 8v-6"></path></svg>
                                    </span>
                                    <strong>Aún no hay resultados</strong>
                                    <span>Completa el formulario para comenzar.</span>
                                </div>
                            <?php endif; ?>
                            <div class="database-note">
                                <span class="status-dot <?= $pdo instanceof PDO ? '' : 'offline' ?>"></span>
                                <?php if ($pdo instanceof PDO): ?>
                                    Conectado a MySQL · <?= h($dbName) ?>
                                <?php else: ?>
                                    MySQL no disponible. Inicia Laragon y revisa la configuración.
                                <?php endif; ?>
                            </div>
                            <?php if (!($pdo instanceof PDO) && $databaseError !== ''): ?>
                                <div class="alert alert-warning" role="alert"><?= h($databaseError) ?></div>
                            <?php endif; ?>
                        </div>
                    </section>
                </div>
            </div>
        </section>

        <section class="history-section container" id="historial">
            <div class="section-heading">
                <div>
                    <span class="eyebrow">Registro de actividad</span>
                    <h2>Historial de operaciones</h2>
                </div>
                <p>Las últimas 30 operaciones realizadas desde este laboratorio.</p>
            </div>
            <div class="panel history-panel">
                <div class="history-top">
                    <div>
                        <h2>Actividad reciente</h2>
                        <p><?= count($history) ?> <?= count($history) === 1 ? 'operación registrada' : 'operaciones registradas' ?></p>
                    </div>
                    <span class="db-status <?= $pdo instanceof PDO ? '' : 'offline' ?>">
                        <span class="status-dot <?= $pdo instanceof PDO ? '' : 'offline' ?>"></span>
                        <?= $pdo instanceof PDO ? 'Base de datos activa' : 'Base de datos desconectada' ?>
                    </span>
                </div>
                <?php if (!($pdo instanceof PDO) && $databaseError !== ''): ?>
                    <div style="padding: 18px 26px 0">
                        <div class="alert alert-warning" role="alert">
                            No se pudo cargar el historial: <?= h($databaseError) ?>
                            <br>Inicia MySQL desde Laragon y verifica las variables CRYPTOLAB_DB_HOST, CRYPTOLAB_DB_PORT y CRYPTOLAB_DB_PASS en tu archivo .env.
                        </div>
                    </div>
                <?php endif; ?>
                <?php if ($history !== []): ?>
                    <div class="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>Algoritmo</th>
                                    <th>Operación</th>
                                    <th>Texto original</th>
                                    <th>Resultado</th>
                                    <th>Clave</th>
                                    <th>Fecha</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($history as $item): ?>
                                    <tr>
                                        <td><span class="algo-label"><?= h((string) $item['algoritmo']) ?></span></td>
                                        <td><?= h((string) $item['operacion']) ?></td>
                                        <td><span class="table-text" title="<?= h((string) $item['texto_original']) ?>"><?= h((string) $item['texto_original']) ?></span></td>
                                        <td><span class="table-text" title="<?= h((string) $item['texto_resultado']) ?>"><?= h((string) $item['texto_resultado']) ?></span></td>
                                        <td><?= h((string) ($item['clave'] ?? '—')) ?></td>
                                        <td><?= h((string) $item['fecha_operacion']) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php elseif ($pdo instanceof PDO): ?>
                    <div class="empty-history">
                        <strong>Aún no hay operaciones</strong>
                        Tus resultados aparecerán aquí después de usar el laboratorio.
                    </div>
                <?php endif; ?>
            </div>
        </section>
    </main>

    <footer>
        <div class="container"><strong>CryptoLab</strong> · Un recorrido por los secretos de la historia.</div>
    </footer>

    <script>
        (() => {
            const algorithm = document.getElementById('algorithm');
            const operation = document.getElementById('operation');
            const keyField = document.getElementById('key-field');
            const key = document.getElementById('key');
            const keyLabel = document.getElementById('key-label');
            const keyHint = document.getElementById('key-hint');
            const operationAnalysis = operation.querySelector('option[value="Analizar"]');
            const encryptOption = operation.querySelector('option[value="Cifrar"]');
            const decryptOption = operation.querySelector('option[value="Descifrar"]');

            function updateFields() {
                if (algorithm.value === 'alkindi') {
                    operation.value = 'Analizar';
                    encryptOption.disabled = true;
                    decryptOption.disabled = true;
                    keyField.hidden = true;
                    key.required = false;
                } else {
                    encryptOption.disabled = false;
                    decryptOption.disabled = false;
                    operationAnalysis.disabled = true;
                    if (operation.value === 'Analizar') operation.value = 'Cifrar';
                    keyField.hidden = false;
                    key.required = true;
                    if (algorithm.value === 'caesar') {
                        keyLabel.textContent = 'Desplazamiento';
                        keyHint.textContent = 'Número de posiciones del alfabeto (0–25).';
                        key.min = '0';
                        key.max = '25';
                        if (Number(key.value) > 25) key.value = '3';
                    } else {
                        keyLabel.textContent = 'Columnas de la vara';
                        keyHint.textContent = 'Número de columnas de la vara (2–50).';
                        key.min = '2';
                        key.max = '50';
                        if (Number(key.value) < 2) key.value = '4';
                    }
                }
                if (algorithm.value === 'alkindi') operationAnalysis.disabled = false;
            }

            algorithm.addEventListener('change', updateFields);
            updateFields();

            const copyButton = document.getElementById('copy-result');
            if (copyButton) {
                copyButton.addEventListener('click', async () => {
                    const text = document.getElementById('result-text').textContent;
                    const label = copyButton.querySelector('span');
                    try {
                        await navigator.clipboard.writeText(text);
                        label.textContent = '¡Copiado!';
                    } catch (error) {
                        label.textContent = 'No se pudo copiar';
                    }
                    window.setTimeout(() => { label.textContent = 'Copiar resultado'; }, 1800);
                });
            }
        })();
    </script>
</body>
</html>
