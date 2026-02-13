<!DOCTYPE html>
<html>
<head>
    <title>NetCheck Diagnostic Tool</title>
</head>
<body>
    <h2>Check Server Availability:</h2>
    <form method="GET">
        Enter IP Address: <input type="text" name="ip">
        <input type="submit" value="Ping!">
    </form>
    <pre>
<?php
    if (isset($_GET['ip'])) {
        $target = $_GET['ip'];

        // VULNERABLE CODE: The input is concatenated directly into a shell command
        // No sanitization or validation is performed on $target.
        $result = shell_exec('ping -c 3 ' . $target);

        echo $result;
    }
?>
    </pre>
</body>
</html>
