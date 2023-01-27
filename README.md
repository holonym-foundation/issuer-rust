# Issuer
## About
## How to Use
run the script with private key as a 32-bit hex string in the `HOLONYM_ISSUER_PRIVKEY` environment variable. Give the two custom fields as `--field1` and `--field2` or `-1` and `-2` in short form. It will return a JSON object with credentials, their corresponding leaf, the issuer's public key, and the issuer's signature of the leaf. 


### Examples

```HOLONYM_ISSUER_PRIVKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cargo run -- --field1 69 --field2 70```

```HOLONYM_ISSUER_PRIVKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cargo run -- -1 123456789 --field2 987654321```

