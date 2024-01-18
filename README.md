# MPC EdDSA FROST

本项目基于：

1. Chelsea Komlo, Ian Goldberg. "FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures." (https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo和Goldberg提供的FROST的PoC代码
   <https://git.uwaterloo.ca/ckomlo/frost>

默认情况下，本项目支持：

1. $(t,n)$-门限Ed25519签名算法Frost（`keygen`、`sign`）；
2. 支持仿BIP32的HD Key衍生；

