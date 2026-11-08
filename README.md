# encrypt_fast

A **performance fork** of [`encrypt`](https://github.com/leocavalcante/encrypt.dart) — 
a set of high-level APIs over PointyCastle for two-way cryptography.

> **Why this fork?** The original `encrypt` package was archived on 2025-06-23.
> This fork adds:
> - A `verifyTag: false` parameter to `decryptBytes()` — **skips per-block GHASH 
>   authentication** for trusted local data, **up to 42× faster** on multi-MB files
> - `decryptBytes()` returns `Uint8List` instead of `List<int>` — a minor 
>   **~2% optimization** (avoids a full copy of the decrypted buffer)
>
> The `verifyTag: false` path is where the real speedup comes from. The 
> `Uint8List` change is small on its own.

> Looking for password hashing? Please, visit 
> [password](https://github.com/leocavalcante/password-dart).

---

## Installation

### From git (recommended)

```yaml
dependencies:
  encrypt_fast:
    git:
      url: https://github.com/ashokavarthanan/encrypt_fast.git
      ref: v5.0.4+fast.1
```

### Local path (for development)

```yaml
dependencies:
  encrypt_fast:
    path: C:\Projects\encrypt_fast
```

---

## Secure random

You can generate cryptographically secure random keys and IVs for your project.

Activate the CLI from your local fork:

```bash
cd C:\Projects\encrypt_fast
dart pub global activate --source path .
```

Then use the `secure-random` command-line tool:

```bash
$ secure-random
CBoaDQIQAgceGg8dFAkMDBEOECEZCxgMBiAUFQwKFhg=
```

You can set the length and the base output.

```bash
$ secure-random --help
-l, --length       The length of the bytes
                   (defaults to "32")

-b, --base         Bytes represented as base 64 or base 16 (Hexdecimal)
                   (defaults to "64")

-h, --[no-]help    Show this help message
```

---

## Algorithms

- AES with PKCS7 padding
- RSA with PKCS1 and OAEP encoding
- Salsa20
- Fernet

### Signing

- SHA256 with RSA

---

## Usage

### Symmetric

#### AES

```dart
import 'package:encrypt_fast/encrypt.dart';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = Key.fromUtf8('my 32 length key................');
  final iv = IV.fromLength(16);

  final encrypter = Encrypter(AES(key));

  final encrypted = encrypter.encrypt(plainText, iv: iv);
  final decrypted = encrypter.decrypt(encrypted, iv: iv);

  print(decrypted);
  print(encrypted.base64);
}
```

##### Modes of operation

Default mode is SIC `AESMode.sic`, you can override it using the `mode` named parameter:

```dart
final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
```

Supported modes are:

- CBC `AESMode.cbc`
- CFB-64 `AESMode.cfb64`
- CTR `AESMode.ctr`
- ECB `AESMode.ecb`
- OFB-64/GCTR `AESMode.ofb64Gctr`
- OFB-64 `AESMode.ofb64`
- SIC `AESMode.sic`
- **GCM `AESMode.gcm`** — see performance section below

##### No/zero padding

To remove padding, pass `null` to the `padding` named parameter on the constructor:

```dart
final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
```

---

### Performance: GCM decryption of large payloads

GCM decryption performs **per-block GHASH authentication** during the decrypt 
loop. This is designed to detect tampering for data in transit, but on large 
local files it dominates the total time (~86% of the cost for multi-MB payloads 
on mid-range Android hardware).

If you are decrypting **data you already trust** (files you created, data from 
a trusted local source, or data you independently validate after decryption), 
you can skip GHASH with `verifyTag: false`.

#### Standard GCM (default — verifies tag)

```dart
import 'package:encrypt_fast/encrypt.dart' as enc;

final cipher = enc.AES(enc.Key(key), mode: enc.AESMode.gcm, padding: null);
final encrypter = enc.Encrypter(cipher);

final decrypted = encrypter.decryptBytes(
  enc.Encrypted(ciphertext),
  iv: enc.IV(iv),
);
// Returns: Uint8List
```

#### Fast mode — skips GHASH

```dart
final decrypted = encrypter.decryptBytes(
  enc.Encrypted(ciphertext),
  iv: enc.IV(iv),
  verifyTag: false,
);
```

**When is `verifyTag: false` safe?**

Only for **trusted local data** where tampering is not a concern:
- Files you created yourself
- Data from a trusted source on the same device
- Cases where you independently validate the output (e.g. a header or format check on the plaintext)

**Do NOT use for:**
- Data received over a network
- Data from untrusted parties
- Any case where tampering detection matters

If the output is corrupt or tampered, `verifyTag: false` will not catch it. 
For any security-sensitive use, keep the default `verifyTag: true`.

#### Benchmark — 1.4 MB payload

**Android 8.1 (Redmi 6 Pro, debug build, real device):**

| Code path | Time | Speedup |
|---|---|---|
| Original `encrypt` 5.0.4 (GCM + `padding:null` + `List<int>`) | 13,534 ms | 1× |
| Fork, `verifyTag: true` (GCM + `padding:null` + `Uint8List`) | 13,280 ms | 1.02× |
| Fork, `verifyTag: false` (CTR + `Uint8List`) | 630 ms | **21.5×** |

**Windows desktop (`dart test`, 1.4 MB synthetic plaintext):**

| Code path | Time | Speedup |
|---|---|---|
| Original `encrypt` 5.0.4 | 1,712 ms | 1× |
| Fork, `verifyTag: true` | 1,654 ms | 1.03× |
| Fork, `verifyTag: false` | 41 ms | **42×** |

**What this shows:**

- The `Uint8List` return type alone saves **~2%** (avoids one full-buffer copy).
- The `verifyTag: false` path saves **~95%** by skipping per-block GHASH.
- The overall speedup depends on file size and hardware. Absolute times vary; 
  the ratio is consistent.

The `verifyTag: false` path uses **AES-CTR with the correct GCM counter 
derivation** (standard NIST J0 + 1), producing **identical plaintext** to the 
GCM path — it simply skips the per-block GHASH accumulation.

---

#### Salsa20

```dart
import 'package:encrypt_fast/encrypt.dart';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = Key.fromLength(32);
  final iv = IV.fromLength(8);
  final encrypter = Encrypter(Salsa20(key));

  final encrypted = encrypter.encrypt(plainText, iv: iv);
  final decrypted = encrypter.decrypt(encrypted, iv: iv);

  print(decrypted);
  print(encrypted.base64);
}
```

---

#### Fernet

```dart
import 'package:encrypt_fast/encrypt.dart';
import 'dart:convert';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');

  final b64key = Key.fromUtf8(base64Url.encode(key.bytes).substring(0, 32));
  final fernet = Fernet(b64key);
  final encrypter = Encrypter(fernet);

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted);
  print(encrypted.base64);
  print(fernet.extractTimestamp(encrypted.bytes));
}
```

---

### Asymmetric

#### RSA

```dart
import 'dart:io';
import 'package:encrypt_fast/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {
  final publicKey = await parseKeyFromFile<RSAPublicKey>('test/public.pem');
  final privKey = await parseKeyFromFile<RSAPrivateKey>('test/private.pem');

  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privKey));

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted);
  print(encrypted.base64);
}
```

---

### Signature and verification

#### RSA

```dart
final publicKey = await parseKeyFromFile<RSAPublicKey>('test/public.pem');
final privateKey = await parseKeyFromFile<RSAPrivateKey>('test/private.pem');
final signer = Signer(RSASigner(
  RSASignDigest.SHA256,
  publicKey: publicKey,
  privateKey: privateKey,
));

print(signer.sign('hello world').base64);
print(signer.verify64('hello world', '...'));
```

---

## Backward compatibility

This fork is **100% backward compatible** with `encrypt` 5.0.4:

- `Uint8List` implements `List<int>`, so existing callers that assign 
  `List<int> x = encrypter.decryptBytes(...)` continue to work unchanged
- `verifyTag` defaults to `true` — no behavior change for existing code
- All 53 upstream tests pass
- No API removals or breaking changes

Migrating from `encrypt`:

```dart
// Before
import 'package:encrypt/encrypt.dart';

// After
import 'package:encrypt_fast/encrypt.dart';
```

That is it. Everything else is unchanged.

---

## Notes

- The original `encrypt` package can be made to skip tag verification by passing 
  `padding: null` to the `AES` constructor. However, it still performs the 
  per-block GHASH computation — so `padding: null` alone does not provide a 
  speedup. Only the fork's `verifyTag: false` skips the GHASH loop entirely.
- Benchmarks above were measured with `padding: null` on both packages, so 
  the comparison isolates the effect of the fork's `verifyTag` parameter 
  and `Uint8List` return type.

---

## License

Same as the original `encrypt` package. See [LICENSE](LICENSE).

---

## Credits

- Original [`encrypt`](https://github.com/leocavalcante/encrypt.dart) by 
  [@leocavalcante](https://github.com/leocavalcante)
- Built on [PointyCastle](https://pub.dev/packages/pointycastle)
- Fork maintained by [@ashokavarthanan](https://github.com/ashokavarthanan)
