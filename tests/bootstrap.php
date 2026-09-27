<?php

declare(strict_types=1);

// Native cookie/session tests must run before any response output is sent.
ob_start();
require dirname(__DIR__) . '/vendor/autoload.php';
