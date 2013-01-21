<?php
require('settings.php');

# Only show whitelisted items
$filtered_list = array();

foreach ($servlist as $s) {
	$filtered_list[] = array(
		'name' => $s['name'],
		'url' => $s['proxy'],
		'encode_url' => $s['encode_url']
	);
}
print json_encode($filtered_list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
?>
