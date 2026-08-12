<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>고려대 대학병원</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body, html { width: 100%; height: 100%; font-family: Arial, sans-serif; }
    a { text-decoration: none; }
    .hero {
      position: relative;
      width: 100%;
      height: 100vh;
      background: url('https://via.placeholder.com/1920x1080') center/cover no-repeat;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .overlay {
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
    }
    .hero-content {
      position: relative;
      text-align: center;
      max-width: 80%;
      z-index: 1;
    }
    .hero-content h1 {
      font-size: 48px;
      margin-bottom: 20px;
      text-shadow: 2px 2px 4px rgba(0,0,0,0.7);
    }
    .hero-content p {
      font-size: 24px;
      margin-bottom: 30px;
      text-shadow: 1px 1px 3px rgba(0,0,0,0.7);
    }
    .hero-content .btn {
      padding: 15px 30px;
      background-color: #005b9e;
      color: #fff;
      font-size: 18px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      transition: background-color 0.3s;
    }
    .hero-content .btn:hover {
      background-color: #004071;
    }
    
    .header {
      position: absolute;
      top: 0; left: 0;
      width: 100%;
      padding: 15px 30px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(0,0,0,0.4);
    }
    .header .logo {
      color: #fff;
      font-size: 24px;
      font-weight: bold;
      text-shadow: 1px 1px 2px rgba(0,0,0,0.7);
    }
    .header nav a {
      margin-left: 20px;
      color: #fff;
      font-size: 16px;
      transition: color 0.3s;
    }
    .header nav a:hover {
      color: #ffd54f;
    }
  </style>
</head>
<body>
  
  <section class="hero">
    <div class="overlay"></div>
    <header class="header">
      <div class="logo">한진 대학병원</div>
      <nav>
        <a href="#">홈</a>
        <a href="#about">병원소개</a>
        <a href="#services">진료과</a>
        <a href="#contact">문의</a>
      </nav>
    </header>
    <div class="hero-content">
      <h1>간암센터 오픈 안내</h1>
      <p>고려대 대학병원 간암센터가 새롭게 문을 열었습니다.<br>최신 의료기술과 전문 의료진이 함께 합니다.</p>
    </div>
  </section>
</body>
</html>