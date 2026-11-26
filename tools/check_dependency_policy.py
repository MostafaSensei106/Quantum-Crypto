"""Reject re-enabling the upstream ML-DSA SIMD verifier affected by RustSec.
This complements cargo audit; it never suppresses advisory reports.
"""
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
features = subprocess.check_output([
    'cargo', 'tree', '--locked', '--manifest-path', str(root / 'rust/Cargo.toml'),
    '-e', 'features', '-i', 'pqcrypto-mldsa'], text=True)
if 'feature "avx2"' in features or 'feature "neon"' in features:
    raise SystemExit('ML-DSA SIMD features must remain disabled pending upstream replacement')
print('ML-DSA dependency policy: portable std backend only')
