# Issuer
## About
This rust script lets you issue credentials to Holonym users. Credentials come with mandatory fields that this takes care:
`issuer_address`, `secret`, `iat`, and `scope`


The other two fields you supply to this. They can be custom, e.g. a user's name, date of birth or phone number. You often need to give a user more than just two credentials. Let's say you want to give them `name`, `birthday`, `country`, and `state`. You can have one (or more) of these fields be a hash of those items. It is up to you to name the fields *outside* of this format. This is serialized, so will ignore all field names; it will just call them `field1` and `field2`. In your schema, you can make `field1` always correspond to `name`, for example, and `field2` always correspond to a `hash(phone_number, birthday)`. 

## How to Use
run the script with private key as a 32-bit hex string in the `HOLONYM_ISSUER_PRIVKEY` environment variable. Give the two custom fields as `--field1` and `--field2` or `-1` and `-2` in short form. It will return a JSON object with credentials, their corresponding leaf, your issuer's public key, and your issuer's signature of the leaf. 


### Examples

```
HOLONYM_ISSUER_PRIVKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cargo run -- --field1 69 --field2 70
```

output
```
"{\"credentials\":{\"address\":\"Fr(0x002c69e750d670c47bdc4746ed2e70469c4a358b7238e9078e63cb0d946426bb)\",\"secret\":\"Fr(0x08c3b2eae0e2a500684caac52108a31c4b522fb44e0cb92407b471a937fa1847)\",\"custom_fields\":[\"Fr(0x0000000000000000000000000000000000000000000000000000000000000045)\",\"Fr(0x0000000000000000000000000000000000000000000000000000000000000046)\"],\"iat\":\"Fr(0x00000000000000000000000000000000000000000000000000000000e77dc566)\",\"scope\":\"Fr(0x0000000000000000000000000000000000000000000000000000000000000000)\"},\"leaf\":\"Fr(0x2cf307ac00e8fd5ee160994d46e4b5e54bf4a01e293fbf986f9d822e404034f7)\",\"pubkey\":[\"Fr(0x1e6a69b9fb7be79b85794b11ff715e247a1f5ef9fa2c76e5ca49cde15a81cf0a)\",\"Fr(0x19a6ce18d4b36b0432145bddd6036c9e9d22e5d739574354f0a49f6fb0d71f3a)\"],\"signature\":{\"r_b8\":[\"Fr(0x25df93f40658ba3c79b6b0c7d05ad2c920a9fa72cfd2b1001625b409946b193f)\",\"Fr(0x1489204f6ad4eb7c2fa5d2cfcb34ff54e96bbc8d8efb8c6287f3aaffb194fb8f)\"],\"s\":\"2309500352302491702815324914508130750890674183808076173255360092305733866859\"}}"
```
```
HOLONYM_ISSUER_PRIVKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cargo run -- -1 123456789 --field2 987654321
```
output
```
     Running `target/debug/main -1 123456789 --field2 987654321`
"{\"credentials\":{\"address\":\"Fr(0x002c69e750d670c47bdc4746ed2e70469c4a358b7238e9078e63cb0d946426bb)\",\"secret\":\"Fr(0x1b417bb6ffc98a35e8eaee66170dc50c227cd1d7f17f7e96bd657e3b7f781e55)\",\"custom_fields\":[\"Fr(0x00000000000000000000000000000000000000000000000000000000075bcd15)\",\"Fr(0x000000000000000000000000000000000000000000000000000000003ade68b1)\"],\"iat\":\"Fr(0x00000000000000000000000000000000000000000000000000000000e77dc5e3)\",\"scope\":\"Fr(0x0000000000000000000000000000000000000000000000000000000000000000)\"},\"leaf\":\"Fr(0x086197c90ab54be380de12050b4f3f4a9b39ef264ecda75809b805fa5f310373)\",\"pubkey\":[\"Fr(0x1e6a69b9fb7be79b85794b11ff715e247a1f5ef9fa2c76e5ca49cde15a81cf0a)\",\"Fr(0x19a6ce18d4b36b0432145bddd6036c9e9d22e5d739574354f0a49f6fb0d71f3a)\"],\"signature\":{\"r_b8\":[\"Fr(0x219cda32edc4373b65e2a2927f98cadd5a944dad9148b34eaab6fe123f2d14d2)\",\"Fr(0x25b2f2a58788bb8b78e6ae15001d8d2eb1f260c6b7c8f58c36919b1afd4cc678)\"],\"s\":\"605684098048337678295141886215007006826395438550092607484630909246260288549\"}}"
```

