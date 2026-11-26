# Historical 0.0.2 benchmark output

These are the original reported numbers, retained for reference. CPU, RAM,
OS, architecture, native build mode and device details were not recorded.
They are not reproducible evidence of a speed advantage or results for 0.0.3.
The historical SLH labels refer to pqcrypto-sphincsplus; deterministic "Kem"
derivation measures HKDF bytes, not ML-KEM key-pair generation. The historical
pipeline labels describe Encrypt-then-Sign despite saying Sign-then-Encrypt.

| Algorithm / Operation | Step | Avg (μs) | Min (μs) | Max (μs) | Median (μs) | Ops/sec |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| **ML-KEM-512** | KeyGen | 96.8 | 78.0 | 1178.0 | 90.0 | 10326.0 |
| **ML-KEM-512** | Encapsulate | 86.2 | 72.0 | 362.0 | 82.0 | 11607.7 |
| **ML-KEM-512** | Decapsulate | 79.7 | 64.0 | 2068.0 | 73.0 | 12545.6 |
| **ML-KEM-512** | Roundtrip | 192.6 | 157.0 | 469.0 | 188.0 | 5191.4 |
| **ML-KEM-768** | KeyGen | 63.6 | 52.0 | 281.0 | 60.0 | 15729.9 |
| **ML-KEM-768** | Encapsulate | 63.4 | 51.0 | 332.0 | 61.0 | 15770.4 |
| **ML-KEM-768** | Decapsulate | 65.6 | 52.0 | 251.0 | 65.0 | 15235.5 |
| **ML-KEM-768** | Roundtrip | 182.0 | 146.0 | 580.0 | 180.0 | 5495.0 |
| **ML-KEM-1024** | KeyGen | 58.5 | 52.0 | 221.0 | 55.0 | 17099.3 |
| **ML-KEM-1024** | Encapsulate | 56.9 | 51.0 | 384.0 | 54.0 | 17572.2 |
| **ML-KEM-1024** | Decapsulate | 60.8 | 55.0 | 283.0 | 58.0 | 16455.8 |
| **ML-KEM-1024** | Roundtrip | 177.9 | 162.0 | 366.0 | 176.0 | 5619.6 |
| **ML-DSA-44** | KeyGen | 65.3 | 57.0 | 233.0 | 62.0 | 15319.3 |
| **ML-DSA-44** | Sign | 112.2 | 67.0 | 407.0 | 99.0 | 8915.2 |
| **ML-DSA-44** | Verify | 65.6 | 60.0 | 251.0 | 63.0 | 15252.3 |
| **ML-DSA-44** | Roundtrip | 244.7 | 190.0 | 621.0 | 230.0 | 4087.0 |
| **ML-DSA-65** | KeyGen | 79.8 | 74.0 | 323.0 | 76.0 | 12529.1 |
| **ML-DSA-65** | Sign | 153.3 | 85.0 | 676.0 | 134.0 | 6523.2 |
| **ML-DSA-65** | Verify | 81.5 | 74.0 | 464.0 | 77.0 | 12268.6 |
| **ML-DSA-65** | Roundtrip | 306.9 | 234.0 | 700.0 | 289.0 | 3258.4 |
| **ML-DSA-87** | KeyGen | 103.8 | 95.0 | 354.0 | 99.0 | 9632.4 |
| **ML-DSA-87** | Sign | 172.7 | 110.0 | 547.0 | 157.0 | 5790.8 |
| **ML-DSA-87** | Verify | 101.2 | 96.0 | 296.0 | 99.0 | 9879.5 |
| **ML-DSA-87** | Roundtrip | 377.6 | 305.0 | 988.0 | 357.0 | 2648.1 |
| **SLH-DSA-SHA2-128f** | KeyGen | 354.5 | 326.0 | 671.0 | 337.0 | 2821.1 |
| **SLH-DSA-SHA2-128f** | Sign | 7400.0 | 6665.0 | 10569.0 | 7366.0 | 135.1 |
| **SLH-DSA-SHA2-128f** | Verify | 684.3 | 638.0 | 951.0 | 654.0 | 1461.3 |
| **SLH-DSA-SHA2-128f** | Roundtrip | 8525.5 | 7912.0 | 10089.0 | 8492.0 | 117.3 |
| **SLH-DSA-SHA2-192f** | KeyGen | 517.9 | 449.0 | 748.0 | 486.0 | 1930.9 |
| **SLH-DSA-SHA2-192f** | Sign | 11482.8 | 10744.0 | 13374.0 | 11430.0 | 87.1 |
| **SLH-DSA-SHA2-192f** | Verify | 1029.8 | 899.0 | 1392.0 | 1046.0 | 971.1 |
| **SLH-DSA-SHA2-192f** | Roundtrip | 13203.0 | 12227.0 | 17817.0 | 13172.0 | 75.7 |
| **SLH-DSA-SHA2-256f** | KeyGen | 1393.6 | 1194.0 | 2272.0 | 1399.0 | 717.6 |
| **SLH-DSA-SHA2-256f** | Sign | 24150.2 | 23015.0 | 25731.0 | 24092.0 | 41.4 |
| **SLH-DSA-SHA2-256f** | Verify | 1165.9 | 972.0 | 6192.0 | 1177.0 | 857.7 |
| **SLH-DSA-SHA2-256f** | Roundtrip | 26899.2 | 25371.0 | 33231.0 | 26879.0 | 37.2 |
| **Hybrid ML-KEM-512** | KeyGen | 63.0 | 58.0 | 314.0 | 60.0 | 15881.1 |
| **Hybrid ML-KEM-512** | Encapsulate | 113.1 | 106.0 | 444.0 | 109.0 | 8844.8 |
| **Hybrid ML-KEM-512** | Decapsulate | 98.1 | 92.0 | 537.0 | 95.0 | 10189.1 |
| **Hybrid ML-KEM-512** | Roundtrip | 276.1 | 258.0 | 522.0 | 270.0 | 3621.7 |
| **Hybrid ML-KEM-768** | KeyGen | 78.3 | 61.0 | 460.0 | 75.0 | 12775.0 |
| **Hybrid ML-KEM-768** | Encapsulate | 127.0 | 113.0 | 393.0 | 121.0 | 7875.2 |
| **Hybrid ML-KEM-768** | Decapsulate | 110.4 | 98.0 | 366.0 | 104.0 | 9055.0 |
| **Hybrid ML-KEM-768** | Roundtrip | 309.7 | 276.0 | 763.0 | 305.0 | 3229.1 |
| **Hybrid ML-KEM-1024** | KeyGen | 78.6 | 69.0 | 352.0 | 75.0 | 12722.3 |
| **Hybrid ML-KEM-1024** | Encapsulate | 125.5 | 115.0 | 308.0 | 119.0 | 7968.2 |
| **Hybrid ML-KEM-1024** | Decapsulate | 111.1 | 103.0 | 295.0 | 106.0 | 9004.0 |
| **Hybrid ML-KEM-1024** | Roundtrip | 319.5 | 290.0 | 575.0 | 317.0 | 3130.1 |
| **AES-256-GCM (1 KB)** | Encrypt | 40.4 | 37.0 | 232.0 | 39.0 | 24735.3 |
| **AES-256-GCM (1 KB)** | Decrypt | 39.4 | 37.0 | 206.0 | 38.0 | 25405.2 |
| **AES-256-GCM (64 KB)** | Encrypt | 293.2 | 254.0 | 685.0 | 288.0 | 3411.2 |
| **AES-256-GCM (64 KB)** | Decrypt | 289.0 | 250.0 | 491.0 | 287.0 | 3460.2 |
| **AES-256-GCM (1 MB)** | Encrypt | 6348.3 | 5492.0 | 9861.0 | 6086.0 | 157.5 |
| **AES-256-GCM (1 MB)** | Decrypt | 6189.9 | 5384.0 | 9274.0 | 6016.0 | 161.6 |
| **ChaCha20-Poly1305 (1 KB)** | Encrypt | 42.7 | 36.0 | 1213.0 | 38.0 | 23392.4 |
| **ChaCha20-Poly1305 (1 KB)** | Decrypt | 40.0 | 36.0 | 288.0 | 38.0 | 25018.1 |
| **ChaCha20-Poly1305 (64 KB)** | Encrypt | 277.9 | 247.0 | 487.0 | 270.0 | 3598.4 |
| **ChaCha20-Poly1305 (64 KB)** | Decrypt | 273.4 | 244.0 | 448.0 | 276.0 | 3657.6 |
| **ChaCha20-Poly1305 (1 MB)** | Encrypt | 6195.7 | 5121.0 | 10439.0 | 5948.0 | 161.4 |
| **ChaCha20-Poly1305 (1 MB)** | Decrypt | 6388.2 | 5229.0 | 11221.0 | 6039.0 | 156.5 |
| **XChaCha20-Poly1305 (1 KB)** | Encrypt | 40.1 | 37.0 | 349.0 | 38.0 | 24929.0 |
| **XChaCha20-Poly1305 (1 KB)** | Decrypt | 38.5 | 36.0 | 271.0 | 37.0 | 25944.4 |
| **XChaCha20-Poly1305 (64 KB)** | Encrypt | 289.3 | 247.0 | 563.0 | 285.0 | 3457.2 |
| **XChaCha20-Poly1305 (64 KB)** | Decrypt | 283.8 | 242.0 | 667.0 | 280.0 | 3523.8 |
| **XChaCha20-Poly1305 (1 MB)** | Encrypt | 5678.1 | 4711.0 | 9779.0 | 5349.0 | 176.1 |
| **XChaCha20-Poly1305 (1 MB)** | Decrypt | 6241.1 | 5019.0 | 11728.0 | 5900.0 | 160.2 |
| **Streaming Encrypt (1MB, 64k)** | Process | 5322.8 | 4255.0 | 9965.0 | 4946.0 | 187.9 |
| **Streaming Decrypt (1MB, 64k)** | Process | 5553.4 | 4333.0 | 10676.0 | 5341.0 | 180.1 |
| **HKDF-SHA256** | Derive | 37.8 | 34.0 | 428.0 | 36.0 | 26440.3 |
| **HKDF-SHA512** | Derive | 37.1 | 34.0 | 223.0 | 36.0 | 26930.2 |
| **SHA-256 (1 KB)** | Digest | 38.8 | 35.0 | 310.0 | 38.0 | 25802.5 |
| **SHA3-512 (1 KB)** | Digest | 39.7 | 37.0 | 201.0 | 38.0 | 25166.7 |
| **Seed Generation** | Generate | 37.0 | 35.0 | 374.0 | 36.0 | 27058.5 |
| **Deterministic Key** | Derive (Kem) | 40.3 | 37.0 | 316.0 | 39.0 | 24829.9 |
| **Sign-then-Encrypt Pipeline** | EncryptAndSign | 252.5 | 176.0 | 830.0 | 234.0 | 3959.7 |
| **Sign-then-Encrypt Pipeline** | VerifyAndDecr | 166.5 | 152.0 | 389.0 | 158.0 | 6006.4 |

