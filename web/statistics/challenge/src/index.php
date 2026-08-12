<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>고려대학병원 Admin 로그인</title>
  <style>
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background-color: #f5f7fa;
      color: #333;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }

    
    header {
      background-color: #0052cc;
      padding: 1rem 2rem;
      color: white;
      display: flex;
      align-items: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    header .logo {
      font-size: 1.5rem;
      font-weight: bold;
    }

    
    .login-container {
      flex: 1;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 2rem;
    }
    .login-card {
      background-color: white;
      padding: 2.5rem 3rem;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      width: 100%;
      max-width: 400px;
    }
    .login-card h2 {
      margin-bottom: 1.5rem;
      font-size: 1.25rem;
      text-align: center;
      color: #0052cc;
    }
    .login-card form {
      display: flex;
      flex-direction: column;
    }
    .login-card label {
      margin-bottom: 0.5rem;
      font-weight: 500;
    }
    .login-card input[type="text"],
    .login-card input[type="password"] {
      padding: 0.75rem 1rem;
      border: 1px solid #ccd0d5;
      border-radius: 4px;
      margin-bottom: 1.25rem;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.2s;
    }
    .login-card input:focus {
      border-color: #0052cc;
    }
    .login-card button {
      padding: 0.75rem;
      background-color: #0052cc;
      color: white;
      font-size: 1rem;
      font-weight: 500;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    .login-card button:hover {
      background-color: #003d99;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">고려대학병원 Admin</div>
  </header>

  <div class="login-container">
    <div class="login-card">
      <h2>관리자 로그인</h2>
      <form onsubmit="return backup(event)">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="아이디를 입력하세요" required />

        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="비밀번호를 입력하세요" required />

        <button type="submit">로그인</button>
      </form>
    </div>
  </div>
  <script>
    function backup(event){
      alert('아직 관리자 페이지 점검 중입니다. 다른 서비스를 이용해주세요.');
    }
  </script>
</body>
</html>
