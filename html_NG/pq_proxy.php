<?

require('settings.php');

// Checking if it is a _GET or a _Post and acting accordingly
error_log("entering the gets and posts");
if (isset($_GET['srv']) || isset($_GET['cmd'])){
	error_log("get: ".$_GET['srv']);
	error_log("get: ".$_GET['cmd']);
}
if (isset($_POST['srv']) || isset($_POST['cmd'])){
	error_log("post: ".$_POST['srv']);
	error_log("post: ".$_POST['cmd']);
}
error_log("exiting the gets and posts");

function get_server_list($filename) {
	$json = file_get_contents($filename);
	return json_decode($json, true);
}

function get_server_hostname($server, $list) {
	foreach ($list as $srv) {
		if ($server == $srv['name']) {
			return $srv['api'];
		}
	}
}

if (isset($_GET['srv'])) {
	$srv = get_server_hostname($_GET['srv'], $servlist);
	$cmd = $_GET['cmd'];
}

if (isset($_POST['srv'])) {
	$srv = get_server_hostname($_POST['srv'], $servlist);
	$cmd = $_POST['cmd'];
}

header("Content-Type:application/json");
header("Access-Control-Allow-Origin: *");

//header("content-type: text/xml");
//echo($svr."".$cmd);

error_log($srv."".$cmd);

$fp = fopen($srv."".$cmd, 'r');
fpassthru($fp);

?>
