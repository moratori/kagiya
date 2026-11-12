# パッケージ管理データベースのテストデータ

実物の rpm / dpkg が作ったデータベースと、同じコマンド自身が報告した一覧（`expected.tsv`）の対。
パーサのテストはこの一覧を「正解」として照合する。

## 出典

| ディレクトリ | 内容 | イメージ | 作成に使ったもの |
|---|---|---|---|
| `rpm-bdb-el8/` | rpm データベース（Berkeley DB、Hash 形式）の `Packages` | `redhat/ubi8@sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e`（RHEL 8.10） | `rpm-4.14.3-32.el8_10` |
| `rpm-sqlite-el9/` | rpm データベース（SQLite）の `rpmdb.sqlite` | `redhat/ubi9@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81`（RHEL 9.9） | `rpm-4.16.1.3-40.el9` |
| `rpm-sqlite-wal/` | 上と同じ DB で、1件の削除が先行書き込みログ（`-wal`）にだけ入っている状態 | 同上 | `sqlite3` |
| `dpkg-ubuntu2404/` | `/var/lib/dpkg/status` の抜粋（6パッケージ分） | `ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5`（Ubuntu 24.04.5） | dpkg |
| `dpkg-ubuntu1604/` | 同上 | `ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6`（Ubuntu 16.04.7） | dpkg |

いずれも arm64 のコンテナで作成した。データベースの形式はアーキテクチャに依存しない（x86_64 と同じリトルエンディアン）。

## 作り方

- **rpm**: 空のデータベースを `rpm --dbpath <dir> --initdb` で作り、ディストリのリポジトリから取得した少数のパッケージ
  （`openssl-libs`、`openssh-server`、`ca-certificates`、`crypto-policies`、`nginx-filesystem`、`httpd-filesystem` のうち取得できたもの）を
  `rpm --dbpath <dir> -i --justdb --nodeps` で登録した。`--justdb` はパッケージのファイルを展開せず、ヘッダ（メタデータ）だけを登録する。
  `expected.tsv` は `rpm --dbpath <dir> -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'` の出力。
- **WAL**: 上の SQLite データベースを `sqlite3` で開き、`PRAGMA wal_autocheckpoint=0` のうえで1行削除し、接続を閉じる前にファイルを複製した。
  `expected.tsv` は、接続を閉じた後（WAL が本体に反映された後）のデータベースを rpm に読ませた結果。
- **dpkg**: `openssl`、`openssh-server`、`nginx-common` を導入してから `nginx-common` を削除し（設定ファイルだけが残った状態を作るため）、
  状態ファイルから対象パッケージの段落だけを抜き出した。
  `expected.tsv` は `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n'` の出力。

データベースのファイルは gzip で圧縮して置いている。

## 含まれる内容とライセンス

データベースに入っているのは、各パッケージのヘッダ（名前、版、説明、ファイル一覧、変更履歴などのメタデータ）であり、パッケージの中身（実行ファイル、ライブラリ）は含まない。
メタデータは各パッケージの配布物の一部で、パッケージごとのライセンスに従う（ヘッダ内の License 項目に記載。例: `openssl-libs` は OpenSSL、`openssh-server` は BSD）。
RHEL のパッケージは Red Hat Universal Base Image のリポジトリから取得したもの。
