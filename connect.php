<?php
$port = @$_GET["port"];
$port = preg_replace("/[^0-9]/", "", $port);

$ip = getenv('REMOTE_ADDR');
$ip = preg_replace("/[^\.0-9]/", "", $ip);

system("perl /var/www/html/slipstream/connect.pl $ip $port");
?>
