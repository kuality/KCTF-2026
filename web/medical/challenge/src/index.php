<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>고려대대학병원 커뮤니티</title>
  <style>
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #eef3f8; color: #222; }
    a { text-decoration: none; color: inherit; }
    ul { list-style: none; }

    
    .container { width: 90%; max-width: 1200px; margin: 0 auto; }

    
    header { background-color: #fff; border-bottom: 2px solid #d1d9e6; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
    .header-inner { display: flex; align-items: center; justify-content: space-between; padding: 1rem 0; }
    .logo a { font-size: 1.75rem; font-weight: 700; color: #005eb8; letter-spacing: -0.5px; }
    nav .menu { display: flex; gap: 1.5rem; }
    nav .menu li a {
      display: block;
      padding: 0.6rem 1.2rem;
      color: #005eb8;
      font-weight: 500;
      border-radius: 6px;
      transition: background-color 0.25s, transform 0.15s;
    }
    nav .menu li a:hover {
      background-color: #e6f2ff;
      transform: translateY(-2px);
    }

    
    main { padding: 2.5rem 0; }
    #board-table {
      width: 100%; border-collapse: separate; border-spacing: 0; background-color: #fff;
      box-shadow: 0 2px 8px rgba(0,0,0,0.05);
      border-radius: 8px;
      overflow: hidden;
    }
    
    #board-table thead th {
      padding: 1rem 1.2rem;
      background-color: #0073c8;
      color: #fff;
      font-weight: 600;
      font-size: 0.95rem;
      letter-spacing: 0.5px;
    }
    
    #board-table thead th:nth-child(1) { text-align: left; }
    #board-table thead th.date-cell,
    #board-table thead th.dept-cell {
      text-align: center;
    }
    #board-table thead th.date-cell { width: 180px; }
    #board-table thead th.dept-cell { width: 140px; }

    
    #board-table tbody tr { border-bottom: 1px solid #ececf0; }
    #board-table tbody tr:nth-child(even) { background-color: #fbfcfe; }
    #board-table tbody tr:hover { background-color: #eaf4ff; }
    #board-table tbody td {
      padding: 0.9rem 1.2rem;
      font-size: 0.93rem;
      color: #333;
    }
    #board-table tbody .title-cell a {
      color: #005eb8;
      font-weight: 500;
      display: block;
    }
    #board-table tbody .date-cell,
    #board-table tbody .dept-cell {
      color: #005eb8;
      font-weight: 500;
      text-align: center;
      white-space: nowrap;
    }
    
    #board-table tbody .dept-cell {
      position: relative;
      color: transparent;
    }
    #board-table tbody .dept-cell::before {
      content: attr(data-dept);
      display: inline-block;
      background-color: #e6f2ff;
      color: #005eb8;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.85rem;
      font-weight: 500;
    }
  </style>
</head>
<body>
  <header>
    <div class="container header-inner">
      <h1 class="logo"><a href="/">고려대대학병원 커뮤니티</a></h1>
      <nav>
        <ul class="menu">
          <li><a href="/">게시판</a></li>
        </ul>
      </nav>
    </div>
  </header>
  <main>
    <div class="container">
      <table id="board-table">
        <thead>
          <tr>
            <th>제목</th>
            <th class="date-cell">생성일</th>
            <th class="dept-cell">진료과</th>
          </tr>
        </thead>
        <tbody>
          <?php 
          
            $conn = new mysqli("medical-revenge-database", "root", "toor", "medical");
            
            $result = $conn->query("SELECT uuid, title, content, create_date, dept FROM board");

            while($row = $result->fetch_assoc()){ ?>
              <tr><td class="title-cell"><a href="/board/read.php?id=<?=$row['uuid']?>"><?=$row['title']?></a></td><td class="date-cell"><?=$row['create_date']?></td><td class="dept-cell" data-dept="<?=$row['dept']?>"></td></tr>
        <? }
          
          ?>
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>
