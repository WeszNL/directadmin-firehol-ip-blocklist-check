#!/usr/local/bin/php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/SernateFireholBlocklistCheck.php';

$force = in_array('--force', $argv ?? [], true);
$result = SernateFireholBlocklistCheck::scheduledCheck($force);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
