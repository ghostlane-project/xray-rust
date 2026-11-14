#!/bin/bash
# Probe (d), the symbol half: which C crypto libraries an archive or binary carries, and
# whether any defined global symbol appears twice.
#
#   ios-symbols.sh <libolc_spike_ios_link.a | binary>
#
# Prints the defined globals per family (BoringSSL unprefixed, aws-lc `aws_lc_*`, ring
# `ring_core_*`, the rest) and every name defined more than once. The link test that settles
# it is a C link with -all_load (scripts/ios-link.sh): ld64 refuses any duplicate there.
set -euo pipefail
f=${1:?archive or binary}
if [ "$(uname)" = Darwin ]; then
  syms=$(nm -gU -j "$f" 2>/dev/null | grep -E '^_' || true)
else
  syms=$(nm -g --defined-only "$f" 2>/dev/null | awk 'NF==3{print $3}' || true)
fi
total=$(printf '%s\n' "$syms" | grep -c . || true)
fam() { printf '%s\n' "$syms" | grep -cE "$1" || true; }
echo "SYMBOLS total=$total"
echo "SYMBOLS aws_lc=$(fam '^_?aws_lc_')"
echo "SYMBOLS ring=$(fam '^_?ring_core_')"
echo "SYMBOLS boringssl_like=$(fam '^_?(SSL_|SSL_CTX_|EVP_|CRYPTO_|OPENSSL_|BIO_|X509_|ERR_|EC_|BN_|RSA_|DTLSv1_|TLS_|d2i_|i2d_|PEM_|ASN1_|HMAC|SHA(1|256|384|512)_?)')"
dups=$(printf '%s\n' "$syms" | grep . | sort | uniq -d || true)
ndup=$(printf '%s\n' "$dups" | grep -c . || true)
echo "SYMBOLS duplicates=$ndup"
printf '%s\n' "$dups" | grep . | head -50 | sed 's/^/DUP /' || true
# What a duplicate is made of, for the first few: the members that define it.
if [ "$ndup" -gt 0 ] && [ "$(uname)" = Darwin ]; then
  for s in $(printf '%s\n' "$dups" | head -5); do
    echo "DUP_MEMBERS $s: $(nm -gU -A "$f" 2>/dev/null | grep -F " $s" | awk -F: '{print $1":"$2}' | sort -u | tr '\n' ' ')"
  done
fi
