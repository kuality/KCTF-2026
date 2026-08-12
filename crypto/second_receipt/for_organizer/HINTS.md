# Hints

1. replay cache가 비교하는 대상과 verifier가 비교하는 대상을 구분하라.
2. Ed25519 signature의 뒤 32바이트는 little-endian scalar이며 canonical 범위가 있다.
3. `S`에 `L=2^252+27742317777372353535851937790883648493`을 더하면 group equation은 변하지 않는다.
