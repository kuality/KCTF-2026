<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>고려대 대학병원 간암센터</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #333; }
    a { text-decoration: none; }
    .header { background-color: #005b9e; color: #fff; padding: 20px; }
    .header .logo { font-size: 24px; font-weight: bold; }
    .nav { display: flex; background-color: #fff; box-shadow: 0 1px 5px rgba(0,0,0,0.1); }
    .nav a { flex: 1; text-align: center; padding: 15px 0; color: #333; border-bottom: 3px solid transparent; transition: border-color 0.3s; }
    .nav a.active, .nav a:hover { color: #005b9e; border-bottom-color: #005b9e; }
    .container { max-width: 1200px; margin: 30px auto; padding: 0 15px; }
    .section { background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .section h2 { color: #005b9e; margin-bottom: 15px; }
    .team-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
    .team-member { text-align: center; }
    .team-member .user-icon { font-size: 120px; color: #ccc; margin-bottom: 10px; }
    .team-member h3 { margin: 5px 0; font-size: 18px; }
    .team-member p { color: #666; }
    .schedule-table { width: 100%; border-collapse: collapse; }
    .schedule-table th, .schedule-table td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    .schedule-table th { background-color: #f1f1f1; }
    .faq-list dt { font-weight: bold; margin-top: 15px; }
    .faq-list dd { margin: 5px 0 10px 20px; line-height: 1.5; }
  </style>
</head>
<body>
  <header class="header">
    <div class="logo">고려대 대학병원 간암센터</div>
  </header>

  <nav class="nav">
    <a href="#intro" class="active">센터 소개</a>
    <a href="#team">의료진 소개</a>
    <a href="#schedule">진료일정</a>
    <a href="#faq">진료 FAQ</a>
    <a href="#resources">관련자료</a>
  </nav>

  <div class="container">
    <section id="intro" class="section">
      <h2>센터 소개</h2>
      <p>고려대 대학병원 간암센터는 소화기내과, 간담췌외과, 영상의학과, 방사선종양학과, 병리과 등 관련 전문 진료과의 협진 시스템을 바탕으로 정확한 진단과 최적의 치료를 제공합니다. 고난이도 간 절제술, 경동맥화학색전술(TACE), 방사선치료, 표적치료제 등 최신 의료기술을 적극 도입하여 환자 맞춤형 통합진료를 실시합니다.</p>
      <p>환자 개개인의 병기, 기능 상태, 생활 환경을 고려한 최적의 치료 옵션을 제시하며, 다학제 협진을 통해 높은 생존율과 삶의 질 향상을 목표로 합니다.</p>
    </section>

    <section id="team" class="section">
      <h2>의료진 소개</h2>
      <div class="team-list">
        <div class="team-member">
          <div class="user-icon">👤</div>
          <h3>박민수 교수</h3>
          <p>소화기내과 • 간암 조기 진단 전문가</p>
        </div>
        <div class="team-member">
          <div class="user-icon">👤</div>
          <h3>김하늘 교수</h3>
          <p>간담췌외과 • 고난이도 간 절제술 전문</p>
        </div>
        <div class="team-member">
          <div class="user-icon">👤</div>
          <h3>이정훈 교수</h3>
          <p>방사선종양학과 • 정밀 방사선 치료 전문가</p>
        </div>
        <div class="team-member">
          <div class="user-icon">👤</div>
          <h3>홍서연 교수</h3>
          <p>영상의학과 • 시술적 중재 치료 담당</p>
        </div>
      </div>
    </section>

    <section id="schedule" class="section">
      <h2>진료일정</h2>
      <table class="schedule-table">
        <thead>
          <tr>
            <th>진료과</th>
            <th>의료진</th>
            <th>진료요일</th>
            <th>진료시간</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>소화기내과</td>
            <td>박민수 교수</td>
            <td>월, 수, 금</td>
            <td>09:00 ~ 12:00</td>
          </tr>
          <tr>
            <td>간담췌외과</td>
            <td>김하늘 교수</td>
            <td>화, 목</td>
            <td>13:00 ~ 17:00</td>
          </tr>
          <tr>
            <td>방사선종양학과</td>
            <td>이정훈 교수</td>
            <td>수, 금</td>
            <td>09:00 ~ 12:00</td>
          </tr>
          <tr>
            <td>영상의학과</td>
            <td>홍서연 교수</td>
            <td>수</td>
            <td>14:00 ~ 16:00</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section id="faq" class="section">
      <h2>진료 FAQ</h2>
      <dl class="faq-list">
        <dt>Q1. 간암은 어떻게 진단하나요?</dt>
        <dd>정기적인 초음파 검사 및 혈액검사(알파태아단백 검사)와 함께 MRI, CT, 조직검사를 통해 정확히 진단합니다.</dd>
        <dt>Q2. 수술이 어려운 간암도 치료가 가능한가요?</dt>
        <dd>고주파열치료술(RFA), 경동맥화학색전술(TACE), 방사선치료 등 다양한 비수술적 치료법을 적용할 수 있습니다.</dd>
        
        <dt>Q3. 치료 후 재발률은 어떤가요?</dt>
        <dd>조기 진단 시 5년 생존율이 높은 편이지만, 재발 가능성이 있어 정기적인 추적 관찰이 매우 중요합니다.</dd>
        <dt>Q4. 입원 기간은 얼마나 되나요?</dt>
        <dd>치료 방식에 따라 다르지만, 평균적으로 5~10일 정도 소요됩니다.</dd>
      </dl>
    </section>
  </div>
</body>
</html>