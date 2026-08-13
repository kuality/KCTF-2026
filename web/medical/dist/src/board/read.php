<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>게시물 상세보기 | 고려대대학병원 커뮤니티</title>
  <style>
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #eef3f8; color: #222; }
    a { text-decoration: none; color: inherit; }
    ul { list-style: none; }

    
    header { background-color: #fff; border-bottom: 2px solid #d1d9e6; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
    .header-inner { display: flex; align-items: center; justify-content: space-between; padding: 1rem 0; width: 90%; max-width: 1200px; margin: 0 auto; }
    .logo a { font-size: 1.75rem; font-weight: 700; color: #005eb8; }
    nav .menu { display: flex; gap: 1.5rem; }
    nav .menu li a { padding: 0.6rem 1.2rem; color: #005eb8; font-weight: 500; border-radius: 6px; transition: background-color 0.25s, transform 0.15s; }
    nav .menu li a:hover { background-color: #e6f2ff; transform: translateY(-2px); }

    
    main { display: flex; justify-content: center; padding: 4rem 0; }
    .card { width: 90%; max-width: 800px; background-color: #fff; padding: 2.5rem 3rem; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    .post-title { font-size: 1.75rem; font-weight: 600; color: #005eb8; margin-bottom: 1rem; }
    .post-meta { display: flex; gap: 1rem; align-items: center; margin-bottom: 2rem; }
    .post-meta .date { font-size: 0.95rem; color: #666; }
    .post-meta .badge {
      display: inline-block;
      background-color: #e6f2ff;
      color: #005eb8;
      padding: 0.3rem 0.8rem;
      border-radius: 12px;
      font-size: 0.85rem;
      font-weight: 500;
    }
    .post-content { font-size: 1rem; line-height: 1.6; color: #333; white-space: pre-wrap; }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <h1 class="logo"><a href="/">고려대대학병원 커뮤니티</a></h1>
      <nav>
        <ul class="menu">
          <li><a href="/">게시판</a></li>
        </ul>
      </nav>
    </div>
  </header>
  <main>
    <div class="card">
      <?php
      require_once __DIR__ . '/../config.php';
      
	      if(isset($_GET['id']) && isset($_GET['secret_key'])){
          $uuid = addslashes($_GET['id']);
          $secret_key = $_GET['secret_key'];
          if (str_contains($secret_key, '.')) exit('Invalid secret key');

          // sleep(2);

          $conn = new mysqli("private-medical-information-center-database", "root", "toor", "medical");
          $result = $conn->query("SELECT title, content, create_date, dept, secret_key FROM board WHERE uuid='".$uuid."' and 0 and secret_key='".$secret_key."'");
          if (!$result) {
                exit('Invalid secret key');
            }

          if($row = $result->fetch_assoc()){
            if($row['secret_key'] !== $secret_key){
              echo "<script>alert('비밀번호가 맞지 않습니다. 다시 확인해주세요.');history.back(-1);</script>";
              exit;
            }
            echo $flag;
            exit;
          }else{
            echo "<script>alert('게시판 번호 값이 존재하지 않거나, 잘못된 번호입니다.');history.back(-1);</script>";
            exit;
          }

        }else{
          echo "<script>alert('게시판 번호 값 또는 secret_key가 누락 되어 있는 것 같습니다. 비밀번호를 추가해주세요.');</script>";
          echo "?id=".$_GET['id']."&secret_key=<SECRET KEY>";
        }
      
      ?>
    </div>
  </main>
</body>
</html>
