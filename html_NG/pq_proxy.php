<?

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

// Checking if it is a _GET or a _Post and acting accordingly
if (isset($_GET['srv']) || isset($_GET['cmd'])){
	$cmd = $_GET['cmd'];

	switch ($_GET['srv']) {
    	case "x.ns.se":
		$svr = "http://xx.xx.xx.xx:8080/";
        	break;
	    	case "y.ns.se":
			$svr = "http://yy.yy.yy.yy:8080/";
        	break;
	}
}

if (isset($_POST['srv']) || isset($_POST['cmd'])){
        $cmd = $_POST['cmd'];

        switch ($_POST['srv']) {
	    	case "x.ns.se":
			$svr = "http://xx.xx.xx.xx:8080/";
	        	break;
		    	case "y.ns.se":
				$svr = "http://yy.yy.yy.yy:8080/";
	        	break;

        }
}


header("Content-Type:application/json");
header("Access-Control-Allow-Origin: *");

//header("content-type: text/xml");
//echo($svr."".$cmd);

error_log($svr."".$cmd);

$fp = fopen($svr."".$cmd, 'r');
fpassthru($fp);

?>
