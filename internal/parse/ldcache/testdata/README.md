# 動的リンカのキャッシュ（/etc/ld.so.cache）のテストデータ

実物の `/etc/ld.so.cache` と、同じ環境の `ldconfig -p` の出力（正解）の対。
キャッシュは `ldconfig` が生成するファイルで、共有ライブラリの名前と場所の一覧だけを含む（ライブラリ本体は含まない）。

| ファイル | イメージ | 備考 |
|---|---|---|
| `ubi9.*` | `redhat/ubi9@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81`（RHEL 9.9、arm64） | 新形式（`glibc-ld.so.cache1.1`）のみ |
| `ubuntu1604.*` | `ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6`（Ubuntu 16.04.7、arm64） | 旧形式（`ld.so-1.7.0`）の後ろに新形式が続く |

どちらも openssl、openssh-server、nginx、Apache httpd を導入した状態で採取した。
