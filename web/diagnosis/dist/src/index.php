<?php require_once 'config.php'; ?>
<?php 

if(isset($_GET['page']) && !preg_match("/iconv|%/i", $_GET['page'])){
  require_once $_GET['page'].".php";
}else{
  require_once 'pages/index.php';
}

?>