# Hints

1. 두 sample의 key뿐 아니라 nonce와 길이도 같은지 확인하라.
2. 한 블록 ciphertext의 GHASH 식 두 개를 XOR하라. 공통 AAD와 length 항은 사라진다.
3. `ΔT=ΔC*H^2`에서 `H`를 구하고, sample tag 하나로 `E_K(J0)`를 복구하라.
