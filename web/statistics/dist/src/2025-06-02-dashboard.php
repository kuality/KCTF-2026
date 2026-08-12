<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>고려대학병원 Admin 대시보드</title>
  <style>
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background-color: #f5f7fa;
      color: #333;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background-color: #0052cc;
      padding: 1rem 2rem;
      color: #fff;
      display: flex;
      align-items: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    header .logo {
      font-size: 1.5rem;
      font-weight: bold;
    }
    main {
      flex: 1;
      padding: 2rem;
    }
    .search-box {
      margin-bottom: 1.5rem;
    }
    .search-box form {
      display: flex;
      align-items: stretch;
      max-width: 400px;
    }
    .search-box input,
    .search-box button {
      padding: 0.75rem 1rem;
      font-size: 1rem;
      border: 1px solid #ccd0d5;
      outline: none;
      transition: border-color 0.2s, background-color 0.2s;
      min-height: 3rem;
    }
    .search-box input {
      flex: 1;
      border-radius: 4px 0 0 4px;
      border-right: none;
    }
    .search-box input:focus {
      border-color: #0052cc;
    }
    .search-box button {
      border: 1px solid #0052cc;
      background-color: #0052cc;
      color: #fff;
      border-radius: 0 4px 4px 0;
      cursor: pointer;
    }
    .search-box button:hover {
      background-color: #003d99;
      border-color: #003d99;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background-color: #fff;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
      border-radius: 4px;
      overflow: hidden;
    }
    thead {
      background-color: #0052cc;
      color: #fff;
    }
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid #e0e0e0;
      font-size: 0.95rem;
    }
    tbody tr:hover {
      background-color: #f1f7ff;
    }
    
    @media (max-width: 600px) {
      th, td { padding: 0.5rem; font-size: 0.9rem; }
      .search-box input, .search-box button { padding: 0.5rem; min-height: 2.5rem; font-size: 0.9rem; }
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">고려대학병원 Admin 대시보드</div>
  </header>
  <main>
    <div class="search-box">
      <form id="searchForm" method="GET">
        <input type="text" id="searchInput" name="name" placeholder="환자 이름으로 검색하세요" />
        <button type="submit">검색</button>
      </form>
    </div>
    <table id="userTable">
      <thead>
        <tr>
          <th>이름</th>
          <th>생년월일</th>
          <th>입원 상태</th>
          <th>진료 상태</th>
          <th>진료 과목</th>
        </tr>
      </thead>
      <tbody>
        <?php 
          $conn = new mysqli("statistics-database", "root", "toor", "medical");
        
          if(isset($_GET['name'])){
            $result = $conn->query("SELECT name, birthday, status, medical_status, medical_subjects FROM users WHERE name='".$_GET['name']."';");
          }else{
            $result = $conn->query("SELECT name, birthday, status, medical_status, medical_subjects FROM users");
          }

          while( $row = $result->fetch_assoc() ){ ?>
              <tr><td><?=$row['name']?></td><td><?=$row['birthday']?></td><td><?=$row['status']?></td><td><?=$row['medical_status']?></td><td><?=$row['medical_subjects']?></td></tr>
    <?php }
        
        ?>        
      </tbody>
    </table>
  </main>
</body>
</html>