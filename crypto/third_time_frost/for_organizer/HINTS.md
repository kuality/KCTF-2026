# Hints

1. 같은 commitment ticket으로 받은 세 server share에서 무엇이 고정되는지 확인하라.
2. RFC 9591의 participant share 식에서 hiding nonce, binding nonce, signing share의 계수를 분리하라.
3. 각 transcript를 `z_j = 1*d + rho_j*e + (lambda_2*c_j)*s_2` 행으로 놓고 `mod L`에서 3x3 선형 시스템을 풀어라.
