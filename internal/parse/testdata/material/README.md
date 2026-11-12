# テスト用の鍵・証明書・キーストア

ここにある鍵はすべて**テスト専用の使い捨て**で、どのシステムでも使われていない。
パスワード付きのものは `kagiya-test-password`。

実物のツールに生成させ、そのツール自身が報告した値（指紋、鍵長など）を `expected.tsv` に記録している。
パーサのテストはこの値を「正解」として照合する。

## 出典

| 生成物 | イメージ | ツール |
|---|---|---|
| OpenSSL / OpenSSH 由来のもの | `debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6`（Debian 13） | OpenSSL 3.5.7、OpenSSH 10.0p2（`TOOLS.txt`） |
| `store.jks`、`store.jceks`、`store-keytool.p12` | `eclipse-temurin@sha256:18bb4a91a3dea3f03ee31d3755af34dfb40f904fc77ab56cdc2f092e32fff9c2` | keytool（Temurin 21.0.13） |

`pkcs12-info.txt` は OpenSSL が各 PKCS#12 ファイルについて報告した保護方式（`openssl pkcs12 -info -noout`）。

## 生成手順の要点

上記イメージのコンテナ内で、次のコマンドで生成した（再生成すると鍵は変わる）。生成に使ったスクリプトは開発者の検証ラボにあり、リポジトリには含めていない。

| ファイル | コマンド |
|---|---|
| `rsa2048-pkcs1.pem`、`rsa3072-pkcs1.pem` | `openssl genrsa -traditional` |
| `rsa2048-pkcs8.pem` | `openssl pkey -in rsa2048-pkcs1.pem` |
| `rsa2048-pkcs8.der` | `openssl pkcs8 -topk8 -nocrypt -outform DER` |
| `rsa2048-pkey.der` | `openssl pkey -outform DER`（OpenSSL 3.5 では PKCS#8 ではなく従来形式が出力されることを `asn1parse` で確認） |
| `rsa2048-pkcs8-enc.pem` | `openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 4096` |
| `rsa2048-pkcs1-enc.pem` | `openssl rsa -traditional -aes128` |
| `ec256-sec1.pem`、`ec384-sec1.pem` | `openssl ecparam -name prime256v1` / `secp384r1` `-genkey -noout` |
| `ec256-pkcs8.pem` | `openssl pkey -in ec256-sec1.pem` |
| `ed25519-pkcs8.pem`、`mldsa65-pkcs8.pem` | `openssl genpkey -algorithm ed25519` / `ML-DSA-65` |
| `dsa2048-pkcs8.pem`、`dsa2048.pem` | `openssl genpkey -paramfile`（2048 ビット）、`openssl pkey -traditional` |
| `*-spki.pem`、`rsa2048-rsapub.pem` | `openssl pkey -pubout`、`openssl rsa -RSAPublicKey_out` |
| `cert-*.pem`、`cert-rsa.der` | `openssl req -new -x509`（`cert-rsa-pss.pem` は `-sigopt rsa_padding_mode:pss`） |
| `csr-rsa.pem` | `openssl req -new` |
| `bundle.p7b`、`bundle-der.p7b` | `openssl crl2pkcs7 -nocrl -certfile cert-rsa.pem -certfile cert-ec.pem` |
| `modern.p12`、`legacy.p12`、`plaincert.p12` | `openssl pkcs12 -export`（それぞれ既定、`-legacy`、`-certpbe NONE`） |
| `ssh-*`、`ssh-*.pub` | `ssh-keygen -t ed25519` / `rsa -b 3072` / `ecdsa -b 256`（`ssh-ed25519-enc` はパスフレーズ付き） |
| `authorized_keys`、`known_hosts` | 上記の公開鍵を並べ、オプション・ホスト名・ハッシュ化ホスト名・`@cert-authority` の行を付けたもの |
| `store.jks`、`store.jceks`、`store-keytool.p12` | `keytool -genkeypair -keyalg RSA -keysize 2048` と `keytool -importcert`（`cert-ec.pem`） |

`expected.tsv` の値の取り方: 公開鍵の指紋は `openssl pkey -pubout -outform DER | openssl dgst -sha256`、証明書の指紋は `openssl x509 -outform DER | openssl dgst -sha256`、
SSH 鍵の指紋と鍵長は `ssh-keygen -lf`、SSH 鍵を X.509 形式に変換したときの指紋は `ssh-keygen -e -m PKCS8 | openssl pkey -pubin -outform DER | openssl dgst -sha256`、
キーストア内の証明書の指紋は `keytool -list -v`。
