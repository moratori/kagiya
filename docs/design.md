# kagiya 設計書（クリプトインベントリ作成ツール）

- 版: 0.5（現在の方針と設計。実測と実装の記録は [records.md](./records.md)、分かっている限界は [limitations.md](./limitations.md) に分けた）
- 日付: 2026-11-14
- 本文中の「Phase 0」〜「Phase 6」は、当初のフェーズ計画（付録 A.3）の区分を指す。いまの進め方は 12 章
- 1〜10 章は当初の設計を土台にしている。2026-11-14 に実装と突き合わせ、実装されていない箇所に【未実装】、実装が設計と違う箇所に【実装と違う】を付けた。一覧は 9.3
- 要件原文: [requirements.md](./requirements.md)
- ツール名（仮）: `kagiya`（鍵屋）

---

## 1. 目的と位置づけ

### 1.1 目的

ツールが稼働するホスト1台の中にある「暗号の利用実態」を、**読み取りのみ・通信なし**で棚卸しし、
機械可読なインベントリ（独自JSON → CBOM / CSV）と、人が読むHTMLレポートを出力する。

PQC移行の初手として使えるだけでなく、将来の危殆化（例: あるハッシュ関数の破綻）が起きたときに
「どのホストのどこでそのアルゴリズムを使っているか」を即答できる台帳を継続的に維持できることを狙う。
そのため量子脆弱なアルゴリズム（RSA, ECDH 等）だけでなく、AES・SHA-2・HMAC 等も区別なく記録する。

### 1.2 既存ツールが苦手な領域（本ツールの差別化点）

| 領域 | 本ツールの方針 |
|---|---|
| 「実効値」の解決 | 設定ファイルに書かれた値だけでなく、未記載項目を「アプリ設定 ＞ OS暗号ポリシー ＞ ライブラリ既定」の順で解決し、**どの層に由来する値か**を記録する |
| レガシー／運用系言語 | 【未実装】ソースコードの解析は対象外とした（1.3、付録 A.1）。Java は、JDK・Tomcat・Spring Boot の設定と、JAR に同梱されたライブラリを扱う |
| Windows の OS 設定 | 【未実装】Schannel・.NET・証明書ストア等をレジストリから直接読む（Windows ではスキャンそのものが未対応。9.3） |
| アプリ固有ストア | Java キーストア（JKS / JCEKS / PKCS#12 / BKS / UBER / BCFKS）、アプリ同梱 CA バンドル等。NSS DB は【未実装】 |
| ソースのないバイナリ | ELF の表層情報（リンクしている暗号ライブラリ）と、JAR の中身の一覧。PE とクラスファイルは読まない（付録 A.2） |
| 閉域・本番環境 | 通信コードを持たない単一バイナリ、低負荷、書き込み先限定 |
| 日本語環境 | 日本語レポート、CRYPTREC 暗号リスト上の位置づけ。Shift_JIS / EUC-JP の設定ファイルのデコードは【未実装】（`x/text` は取り込んでいない） |

### 1.3 非目標（やらないこと）

- ネットワーク越しの調査全般（ポートスキャン、TLS ハンドシェイクによる実測、リモートホスト調査）
- クラウド事業者の管理面（KMS、証明書マネージャ、ロードバランサ設定等）の調査
- 外部コマンドの実行（`nginx -V`、`openssl version`、`rpm -q` 等も実行しない。理由は 5.3）
- ソースコードの解析（このツールを動かすサーバー上には、ソースコードがないと考えられるため。開発環境の CI/CD に組み込む別種のツールに任せる。付録 A.1）
- ELF/PE の逆アセンブル・逆コンパイル、クラスファイルやバイナリから「どの暗号 API を参照しているか」を拾うこと（付録 A.2）
- アプリ層の暗号の設定（Laravel / Rails / CakePHP の設定ファイルにある暗号化やハッシュの方式など。設定がコードで書かれており、ソースコードを見ないという方針に反する）
- 実行中のプロセスを調べること（既定では行わない。明示的に指定したときだけ読む機能を、最も優先度の低い将来のタスクとしている。12 章、付録 A.4）
- 商用のアプリケーションサーバー（WebLogic、WebSphere など。商用ソフトのイメージを使わない決まりのため、実物で確かめられない）
- 脆弱性（CVE）スキャン、シークレットスキャン（ハードコード鍵の「存在」は記録するが網羅は目標外）
- 設定の変更・修復、移行の自動実行
- 複数ホストの集中管理サーバ／エージェント常駐（結果ファイルを持ち寄ってレポート化する運用とする）
- v1 では対象外: コンテナイメージ層（`/var/lib/docker` 等。ホストからは既定で除外し記録。コンテナ内で本ツールを実行することは可能）、
  他ユーザーの未ロードのレジストリハイブ、HSM/TPM 内部の鍵、メモリ上の鍵

---

## 2. 言語の選定

### 2.1 結論: Go（`CGO_ENABLED=0` の純 Go 静的リンク）

### 2.2 選定理由

| 観点 | Go の評価 |
|---|---|
| 単一実行ファイル・ランタイム不要 | 純 Go 静的バイナリ。libc に依存しないため glibc の版差（Ubuntu 16.04 の 2.23 ～ 最新）を気にしなくてよい |
| クロスビルド | `GOOS/GOARCH` 指定だけで linux/amd64, linux/arm64, windows/amd64 を生成できる |
| 標準ライブラリで足りる範囲 | `debug/elf`, `debug/pe`, `debug/buildinfo`, `archive/zip`, `encoding/asn1`, `encoding/pem`, `encoding/xml`, `embed`, `regexp`。サードパーティ依存を最小化でき、サプライチェーンリスクと監査コストが小さい |
| 通信しないことの検証可能性 | 依存パッケージグラフから `net`（ソケット実装）と `os/exec` を**排除してビルドできる**。「バイナリに通信コードが存在しない」ことを CI で機械的に検査できる（4.2） |
| 暗黙の通信の排除 | cgo を使わないため glibc の NSS（LDAP/SSSD 等への問い合わせ）を経由しない |
| 悪意ある入力への耐性 | メモリ安全。`regexp` は RE2 系で線形時間（ユーザー定義ルールでも ReDoS が起きない）。`encoding/xml` は DTD・外部実体を解決しない。ただし `debug/elf`・`debug/pe` は敵対的入力への堅牢性が保証されていない（2.4） |
| 監査しやすさ | 導入企業のセキュリティ部門がソースを読む場面を想定。言語仕様が小さく読みやすい |

### 2.3 他候補を採らなかった理由

- **Rust**: 安全性・単一バイナリは同等以上。ただし ELF/PE/ZIP/ASN.1/テンプレート等をクレートに頼ることになり、依存の監査コストが増える。次点。
- **C/C++**: 信頼できない入力（任意のファイル）を大量にパースするツールでメモリ安全でない言語は不適。
- **Python / Java / .NET / Node.js**: ランタイムが必要、またはランタイム同梱で巨大化・起動時展開（＝出力先以外への書き込み）が発生する。
- **PowerShell / シェル**: OS ごとに別実装となり、バイナリ解析等が困難。

### 2.4 Go 採用に伴う弱点と対策

- `crypto/x509` は `net` を import し、未知アルゴリズムや不正気味の証明書に厳格。→ **使用しない**。証明書・鍵は自前の ASN.1 リーダで読む（OID をルール側の表で解決するので、新アルゴリズム追加がルール変更で済む利点もある）。
  PKCS#12 や PKCS#7 は BER（不定長）で書かれることが多く、標準の `encoding/asn1` は BER を拒否するため、リーダは **BER 対応**とする。自作するパーサの量は小さくない（付録 A.3 のリスク）。
- `golang.org/x/sys/windows`（レジストリ含む）は `net` を import する（実測で確認）。→ **使用しない**。Windows API は標準 `syscall` 上の自前ラッパを `internal/platform` に書く。
  DLL は System32 からのみロードする指定（`LOAD_LIBRARY_SEARCH_SYSTEM32`）で読み込み、DLL 植え付けを防ぐ。
- `debug/elf`・`debug/pe` は公式に「敵対的入力に対して堅牢化されていない」とされ、巨大なメモリ確保があり得る（panic は回復できるがメモリ圧迫は回復できない）。
  → ヘッダのセクション数・サイズを事前検証してから渡すか、必要部分だけ読む上限付きの自前リーダにする（Phase 5 で決定）。
- `os/user` は Windows でドメインコントローラへの問い合わせを起こし得る。→ **使用しない**。UID / SID は数値・文字列のまま出力する。
- 優先度・seccomp 等はスレッド単位の属性で、Go は起動時から複数スレッドを持つ。→ 全スレッド適用の仕組みを使い、適用結果を検証する（4.2、6章）。
- ガベージコレクションとコピーのため、メモリ上の秘密のゼロクリアは保証できない。→ 秘密鍵ファイルは必要最小部分だけ読む方針で補う。
- Go 製バイナリはアンチウイルスに誤検知されやすい傾向がある。→ 最初の配布から署名し、ハッシュを公開する。【実装と違う】リリースはチェックサム（SHA-256）の公開だけで、署名は付けていない。
- Go の最小対応 OS（Go 1.27 は Wiki 上 Windows 10 / Server 2016、Linux カーネル 3.2）は **Phase 0 に実機／実イメージで検証**する。
- 外部依存は次に限定し、`vendor/` に固定する: `golang.org/x/sys/unix`、`golang.org/x/text`（Shift_JIS/EUC-JP/UTF-16 デコード）、保守されている YAML パーサ1つ（選定条件は 7.3）。【実装と違う】実際の外部依存は YAML パーサ（`go.yaml.in/yaml/v3`）だけ。`x/sys/unix` と `x/text` は使っていない（システムコールは標準の `syscall` を `internal/platform` で使う）。CI は `-mod=vendor`・`GOPROXY=off` でビルドする。

---

## 3. 全体構成

### 3.1 実行形態

- 単一プロセス・単一バイナリ。常駐しない。プロセス間通信・子プロセス起動なし。
- 処理はプロセス内のパイプライン。並行度は 1 で固定（並行処理は実装していない）。
- 【実装と違う】下の図は当初の案。実際のコレクタは `osconf`（OS の暗号設定）、`pkgs`（パッケージ情報）、`bins`（アプリの本体がリンクするライブラリ）、
  `apps`（サーバーアプリの設定と実効値）、`fscrawl`（証明書・鍵・キーストア）、`jars`（JAR に同梱されたライブラリ）。`source` はない（1.3）。
  証明書ストアは独立したコレクタではなく、`fscrawl` が見つけたファイルに、ルール（`os/stores.yaml`）でストアの名前を付ける。出力は JSON だけで、CBOM / CSV は `convert` で作る。

```
            ┌──────────── kagiya (単一プロセス) ────────────┐
 ルール      │  rules ローダ（内包 or --rules 指定ディレクトリ） │
 (内包/外部) ─▶│        │                                      │
            │        ▼                                      │
 ローカル    │  collectors ──▶ 正規化(catalog) ──▶ 重複統合 ──▶ writer ──▶ 出力ディレクトリ
 ファイル/   │   ├ os-policy      ▲                              │      (JSON / CBOM / CSV)
 レジストリ ─▶│   ├ apps ─────▶ resolver(実効値解決)             └──▶ ログディレクトリ
 (safefs経由) │   ├ certstores                                   │
            │   ├ fs-crawl (証明書/鍵/キーストア/バイナリ)        │
            │   ├ source                                        │
            │   └ binary                                        │
            └───────────────────────────────────────────────┘
```

### 3.2 サブコマンド

| コマンド | 役割 |
|---|---|
| `kagiya scan` | ホストをスキャンし結果 JSON を出力（CBOM / CSV を同時に出す指定は【未実装】。`convert` で変換する） |
| `kagiya convert` | 結果 JSON を CBOM / CSV に変換 |
| `kagiya report` | 結果 JSON（1 個以上、最大 200 個）から単一 HTML を生成。集約 JSON の入力は【未実装】 |
| `kagiya merge` | 【未実装】多数の結果 JSON を1つの集約 JSON にまとめる（数百〜数千ホスト向け。7.4） |
| `kagiya rules export` | 内包ルールを指定ディレクトリに書き出す |
| `kagiya rules validate` | ルールディレクトリの構文・整合性を検証 |
| `kagiya version` | ツール版・内包ルール版・ルールの SHA-256（先頭 12 桁）を表示 |

主なオプション（`scan`。実装されているもの）:

```
--output-dir DIR        結果の出力先（既定: カレントディレクトリ）
--log-dir DIR           ログ出力先（既定: ./logs）
--roots PATH,...        ファイルシステム探索の起点（既定は 5.5 の既定リスト。指定しない場合は、ルールにある証明書ストアの場所も起点に加わる）
--exclude GLOB,...      除外パス（複数可）
--rules DIR             外部ルールディレクトリ（指定時のみ読み込む。内包ルールを置き換える）
--max-file-size N       1ファイルの読み取り上限（MiB の整数。既定 64）
--cpu-limit / --io-limit  CPU 使用率・読み取り速度の上限（6章）
--strict                スキップ・エラーがあれば終了コード 1
--max-duration DUR      実行時間上限（超過時は途中結果を「未完了」と明記して終了）
--label K=V             台帳連携用の任意タグ（システム名、管理部署など）
```

【未実装】当初の設計にあった次のオプションは、実装していない:
`--exclude-from FILE`（除外の一括指定）、`--collectors LIST`（コレクタの選択。常にすべて実行する）、`--format json,cbom,csv`（追加の出力形式）、
`--workers N`（並行度。1 で固定）、`--rules-mode replace|overlay`（常に置き換え）、`--process-info`（稼働プロセスの情報。1.3、付録 A.4）、
`--dry-run`（計画だけを出して終了）。

- アプリケーションとして環境変数・カレントディレクトリ・ホームディレクトリから設定やルールを**暗黙に読み込まない**。
  Go ランタイム自体が読む環境変数（`GODEBUG`、`GOTRACEBACK` 等）は、設定されていたら警告を記録し、危険なもの（コア出力）は起動時に無効化する（4.2）。
  【未実装】環境変数の警告と、トレースバックの設定の固定は実装していない（コアダンプの無効化は実装済み）。
- 終了コード: `0` 完了（スキップがあっても正常。ネットワーク FS のスキップ等は通常の動作のため） / `1` `--strict` 指定時にスキップ・エラーあり / `2` 引数エラー / `3` 致命的エラー・未完了。ジョブ管理ツールからの実行を想定。
- 出力ファイル名: `kagiya-<ホスト名>-<UTC日時>-<scan_id 短縮>.json`（定期実行で衝突しない）。既存ファイルは上書きしない。
- `--exclude` は `**` を含むグロブ。Windows では大文字小文字を区別しない（Windows のスキャンは【未実装】）。標準エラー出力の進捗は件数のみ（パスを出さない）。
- 時刻は UTC で扱う（タイムゾーンデータベースの読み込みを避ける）。

### 3.3 パッケージ構成

【実装と違う】下は設計時の案。実際の構成は 3.4。主な違い: `internal/rules` と `internal/catalog` は `internal/ruleset`（と `rules/embed.go`）、
`internal/resolve` は `internal/tlsciphers`・`tlseffective`・`tlsgroups`・`jsse`・`tomcatciphers` に分かれた。コレクタは `collect/{osconf, pkgs, bins, apps, fscrawl, jars}`。
`internal/output` は安全なファイル作成だけを受け持ち、CBOM / CSV への変換は `internal/convert`。最上位の `testdata/` はなく、テストデータは各パッケージの `testdata/` に置く。

```
cmd/kagiya/            エントリポイント
internal/cli/          引数解析、サブコマンド
internal/safefs/       ★ファイルを開く唯一の経路。ネットワークFS判定、除外、サイズ上限、権限エラー記録
internal/platform/     OS依存（優先度低下、マウント表、レジストリ読取、出力ファイルの権限、サンドボックス）
internal/rules/        ルールの読み込み・検証・書き出し（内包は go:embed）
internal/catalog/      暗号カタログ（別名→正規ID、評価情報）
internal/parse/        形式パーサ群（der, pem, keystore, elf, pe, classfile, 各設定文法）
internal/collect/      コレクタ群（ospolicy, apps, certstore, fscrawl, source, binary）
internal/resolve/      実効値解決（解決チェーン、OpenSSL 暗号文字列の展開など）
internal/model/        データモデル（結果 JSON の型）
internal/output/       json / cbom / csv
internal/report/       HTML 生成（テンプレートと CSS/JS を内包）
internal/logx/         ログ
rules/                 内包ルール定義（YAML）
testdata/              ディストリ別・版別の実設定ファイル等のフィクスチャ
```

設計上の柱: **ファイルを開く処理は `safefs` だけ**、**書き込みは `output` と `logx` だけ**に集約する。
個別関数の禁止では漏れる（`os.ReadFile`、`filepath.Walk`、`elf.Open`、`zip.OpenReader` 等も内部でファイルを開く）ため、
**`os` と `path/filepath` の import 自体を `cmd/kagiya` / `cli` / `safefs` / `platform` / `output` 以外で禁止**し（`logx` は `os` を使わず、書き込み先を外から受け取る）、パーサは `io.ReaderAt` 等のインターフェースだけを受け取る。CI の静的検査で強制する。

### 3.4 コードの構成（2026-11-12 のリファクタリング後）

3.3 のパッケージ構成は設計時の案で、実装では次のようになっている（★は、版やアプリによらない共通の部品）。

| パッケージ | 役割 |
|---|---|
| `internal/model` | 結果 JSON の型。`vocab.go` に、結果に現れる決まった値（実効値の状態、確度、利用の確からしさ、項目名、評価の値）を定数として持つ |
| `internal/ruleset` | ルール（データ）の読み込みと検証。`ruleset.go`（入口と共通の検証）、`catalog.go`、`stores.go`、`packages.go`、`apps.go`、`defaults.go`、`ciphers.go`、`policy.go` |
| `internal/parse/*` | ★形式ごとのパーサ（DER、証明書、鍵、キーストア、パッケージ DB、ELF、各設定ファイルの文法） |
| `internal/tlsciphers` | ★OpenSSL の暗号文字列の展開（手順だけ。値は対応表から） |
| `internal/tlseffective` | ★OpenSSL を使うサーバーが実際に使えるスイートの計算 |
| `internal/assess` | ★評価ポリシーによる判定。設定項目と「評価での名前の種類」の対応もここに 1 か所だけ持つ |
| `internal/collect/apps` | アプリの設定の収集。共通: `apps.go`（入口）、`units.go`（ユニット）、`settings.go`（設定値の検証と記録）、`defaults.go`（既定値表の引き当て）、`tlsserver.go`（TLS サーバーの実効値）、`tlsgroups.go`（受け入れる鍵交換のグループ）。アプリごと: `sshd.go`、`nginx.go`、`apache.go`、`haproxy.go` |
| `internal/report` | HTML レポート。`report.go`（入口）、`view.go`（表示用のデータの型と要点の数え方）、`labels.go`（文言）、`services.go`、`assets.go`（表示用のデータの組み立て）、`render.go`（HTML の書き出しとエスケープの規則）、`style.css` |

リファクタリングで守ったこと: 動作を変えない（テストは変更せず、整理の前後で同じサンプルからのレポートが 1 バイトも変わらないことを確かめた）。

整理した内容:

- **同じ知識が 2 か所以上にあったものを 1 か所にした。** 設定項目と評価での名前の種類の対応（評価とレポートに別々にあった）、パッケージの版の文字列の作り方（3 か所）、
  暗号文字列の妥当性の確認（3 か所）、暗号文字列の長さの上限。
- **文字列のまま散らばっていた決まった値を定数にした。** `resolved` / `unresolved`、`high` / `medium`、`enabled` / `installed` など。
- **レポートの数え方を、表示名の比較から評価の値の比較に変えた。** 表示の文言を変えても、数が変わらない。
- **大きなファイルを役割ごとに分けた。** `report.go`（931 行）、`ruleset.go`（855 行）、`apps.go` と `tlsserver.go`。

あえて残したもの:

- 読み飛ばしの理由の文字列（`config-problem`、`permission-denied` など）は、`safefs` と各コレクタに文字列のまま残っている。レポートの表示名との対応は `labels.go` の 1 か所。
- 鍵長や件数の上限（`256`、`1024`、`4096` など）は、パーサごとに意味の違う値なので、それぞれのパーサの中の名前付き定数のままにしている。
- 検証ラボの生成スクリプト（`lab/`）には、同じ処理の写しがいくつかある。リポジトリの外で、本体の動作には関わらない。

その後に足したパッケージ（2026-11-13〜14）:

| パッケージ | 役割 |
|---|---|
| `internal/jsse` | JDK の TLS の対応表と設定から、受け入れるプロトコル・スイート・グループを求める |
| `internal/tomcatciphers` | Tomcat の暗号指定（OpenSSL の書き方）を、Tomcat の表で解釈する |
| `internal/parse/javasecurity`、`serverxml`、`springconf`、`javacmd`、`jarfile` | `java.security`、Tomcat の `server.xml`、Spring Boot の設定、Java の起動コマンド、JAR（zip）の読み取り |
| `internal/collect/jars` | JAR に同梱された暗号ライブラリの記録 |
| `internal/parse/supervisorconf`、`shellconf` | supervisord の設定、シェルが取り込む「名前=値」だけの設定ファイル（Spring Boot の実行できる JAR の `.conf`） |

上の 2 つの表にない主なパッケージ: `internal/inventory`（結果の組み立てと ID）、`internal/convert`（CBOM / CSV）、`internal/output`（安全なファイル作成）、
`internal/throttle`（流量制限）、`internal/tlsgroups`（鍵交換のグループ）、`internal/buildcheck`（禁止 import・依存・シンボルの検査）、
`internal/collect/{osconf, pkgs, bins, fscrawl}`、`internal/parse/{unitfile, postfixconf, dovecotconf, mycnf, pgconf, haproxyconf, stunnelconf, ldcache, pkgdb, elfdyn, opensslcnf, sshdconf, nginxconf, apacheconf, keymat, keystore, x509cert, der}`。
`internal/collect/apps` には、アプリごとのファイルとして `postfix.go`、`dovecot.go`、`mysql.go`、`postgresql.go`、`stunnel.go`、`java.go`、`tomcat.go`、`tomcat_install.go`、
`springboot.go`、`executable.go`、`javalaunch.go` もある。`internal/ruleset` には `groups.go`、`javalib.go`、`jdk.go`、`tomcat.go` もある。

---

## 4. 安全設計（禁止事項への対応）

### 4.1 禁止事項と対応の一覧

| 禁止事項 | 対応 |
|---|---|
| 出力先以外に書き込まない | 書き込みは出力ディレクトリとログディレクトリのみ（ログ先は要件で認められた例外）。一時ファイルを作らない（メモリ上で処理、または出力先に `.partial` で書いてリネーム）。スキャン対象は読み取り専用で開く |
| ポート待ち受け・外部通信なし | 4.2 の三層防御 |
| ネットワーク FS を読まない | 4.3 |
| 暗黙の通信 | 4.4 |
| 秘密値を出さない | 4.5 |
| 自動更新・テレメトリなし | 実装しない。通信コードがないため構造的に不可能 |
| 出力は作成者のみ可読 | 4.6 |
| CPU 優先度を下げる | 6章 |

### 4.2 通信しないことの保証（三層）と、その保証範囲

**保証範囲の定義**: 「本プロセスがソケット等の通信 API を使わない」「ネットワーク越しのファイルシステム（NFS/SMB 等）と、開くと取得が発生するファイルに触れない」まで。
次のものは本ツールでは検出・制御できず、保証範囲外として利用者向け文書に明記する:
ブロックレベルのネットワークストレージ（iSCSI/SAN/NBD 等）上のローカル FS、アンチウイルス・EDR のクラウド照会、OS の監査ログ転送など第三者による間接的な通信。

1. **通信コードを持たない（ビルド時保証）**
   - 依存グラフ（vendor 含む）に `net`、`net/http`、`os/exec`、`plugin`、`crypto/tls`、`crypto/x509`、`os/user` が含まれないことを CI で検査する。`text/template` と `html/template` も禁止している（名前からメソッドを呼ぶ仕組みが入ると、リンカが未使用の通信用メソッドを捨てられなくなるため）。
     レビューでの実測により、本設計が使う標準パッケージ・`x/sys/unix`・`x/text`・YAML パーサはこれらを引き込まないことを確認済み。
   - `syscall` / `unsafe` / `//go:linkname` / アセンブリは任意のシステムコールを呼べるため、使用を `internal/platform` のみに許可する静的検査を置く（vendor も対象）。`internal/platform` は小さく保ち、重点レビュー対象とする。
   - Linux: 生成バイナリにソケット・exec 系シンボルが無いことを検査（実測で確認済み）。
   - Windows: 標準 `syscall` パッケージ由来の**未使用の** Winsock/DNS API 定義（遅延ロード用の名前）がバイナリ内に残ることを実測で確認した。したがって Windows での主張は
     「`net` を含まず、通信 API を呼ぶコード経路がない。`ws2_32.dll` 等はロードされない」とし、実行時にロード済みモジュールを列挙して `ws2_32` / `dnsapi` / `winhttp` / `wininet` が無いことを検査する結合テストで裏付ける。
     【未実装】この結合テストはない（Windows のスキャンが未対応のため。CI はシンボルを見るだけ）。
2. **触れない（実行時の回避）**: 4.3。
3. **できない（実行時の封じ込め、ベストエフォート）**
   - Linux: seccomp フィルタ（`SECCOMP_FILTER_FLAG_TSYNC` で全スレッドに適用、`seccomp_data.arch` を検査して 32bit ABI 経由の迂回を防止、
     `socket`/`connect`/`bind`/`listen`/`accept*`/`sendto` 等に加え `execve`/`execveat`/`io_uring_*`/`ptrace`/`process_vm_*` を拒否、違反時は `EPERM`）。`PR_SET_NO_NEW_PRIVS` は全スレッドに適用。
     実装では、マウント系（`mount`、`umount2`、`open_tree`、`move_mount`、`fsopen` など）と鍵保管庫（`add_key`、`request_key`、`keyctl`）も拒否している。amd64 / arm64 以外では適用しない（`unsupported` と記録）。
   - Windows: Job オブジェクトで子プロセス生成を禁止。不要な特権をトークンから削除。【未実装】
   - Landlock（書き込み先限定）は必須対象 OS の多く（RHEL 8、Ubuntu 20.04 以前）に存在しないため v1 では扱わない。
   - 適用結果は `meta.hardening` とログに記録。適用できなくてもスキャンは続行（層1・2が主たる保証）。
   - 管理者が OS 側で本バイナリの通信を遮断する手順（ファイアウォール規則等）も文書で案内する。

コアダンプ・クラッシュレポート対策: 起動直後にコアダンプを無効化し（`RLIMIT_CORE=0`、`PR_SET_DUMPABLE=0`）、Go のトレースバック設定を固定する
（`GOTRACEBACK=crash` によるコア出力や Windows エラー報告への引き渡し＝出力先以外への書き込み・秘密流出・通信を防ぐ）。
【未実装】トレースバックの設定の固定は実装していない（コアダンプの無効化は実装済み）。

検証手段: ネットワーク名前空間を切り離した環境と `strace -f -e trace=network` 下の結合テストを CI に組み込み、利用者が再現できる手順として文書化する。
【実装と違う】CI にあるのは `strace` 下の結合テスト（`ci/verify-linux.sh`）だけ。ネットワーク名前空間を切り離したテストは【未実装】。

### 4.3 ネットワークファイルシステム等の回避

**原則1: 触れる前に判定する。** 自動マウント（autofs）は stat だけでマウント＝通信が起き、NFS は `statfs` でも通信するため、判定はマウント表とすでに開いたハンドルの情報だけで行う。
**原則2: パス文字列ではなくディレクトリハンドル相対で辿る。** パス文字列で開くと途中要素のシンボリックリンクが辿られ、判定後の差し替え（競合）も起きるため。
【実装と違う】探索（`safefs` の Walker）はディレクトリハンドル相対（`os.Root`）で辿る。一方、設定ファイルなどを名前で開く経路（`safefs` の Opener）は、
1 要素ずつマウント表と照合して `lstat` で確かめた後、パス文字列で開き（リンクは辿らない指定）、開いたものが確かめたものと同じかを照合する。途中の要素の差し替えは、この照合では検出しきれない。

Linux:
- `/proc/self/mountinfo` からマウント表を構築（`\040` 等のエスケープ、重ねマウントを正しく扱う）。種別が拒否リスト
  （`nfs*`, `cifs`, `smb*`, `ceph`, `glusterfs`, `lustre`, `gpfs`, `beegfs`, `9p`, `afs`, `ncpfs`, `davfs`, `fuse.sshfs`, `autofs` ほか）のマウントポイント配下は**システムコールを発行せずに**スキップ。
  許可リストにない `fuse.*` や未知の種別は既定スキップ（安全側）。リストはルールで拡張可能。【実装と違う】種別の表はコード（`safefs.DefaultPolicy`）に持っており、ルールでは拡張できない。
- overlayfs は `lowerdir`/`upperdir` の所在、loop デバイスは backing file の所在も判定に含める。【未実装】overlayfs は無条件にローカルとして扱っている。
- 走査は `openat` + `O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK` で1要素ずつ。`fstatat` には `AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT`。カーネルが対応していれば `openat2`（`RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`）を使う。【未実装】`openat2` と `AT_NO_AUTOMOUNT` の明示的な指定は使っていない（自動マウントは、マウント表の種別で触れる前に避ける）。
- 開いた後の再確認は `fstat` の `st_dev` とマウント表の major:minor の照合で行う（`fstatfs` は使わない）。btrfs サブボリューム等、マウント境界でなくても `st_dev` が変わる場合を考慮する。
- 探索ではシンボリックリンクを辿らない。設定ファイルが参照するパス（証明書ファイル等）は、**1要素ずつマウント表と照合しながら自前で解決**する（`realpath` 相当の一括解決は使わない）。
- `proc`, `sysfs`, `devtmpfs` 等の擬似 FS は探索しない（OS 設定取得のための特定ファイルの直接読取のみ）。
- 稼働プロセスの情報（5.3）は、マウント名前空間が自プロセスと同じプロセスに限る。異なるもの（コンテナ内プロセス等）は対象外として記録。【未実装】（プロセスは読まない）

Windows（【未実装】Windows ではスキャンができない）:
- `DRIVE_REMOTE` のドライブ、UNC パス、`subst`／ネットワーク割り当てドライブは対象外。
- 1要素ずつ `FILE_FLAG_OPEN_REPARSE_POINT` 付きで開き、リパースポイント（ジャンクション、シンボリックリンク、マウントポイント）は辿らない。
- クラウド同期のプレースホルダ（`RECALL_ON_DATA_ACCESS` / `RECALL_ON_OPEN` / `OFFLINE` 属性）は、ファイルは開かず、ディレクトリは列挙しない。属性は親ディレクトリの列挙結果から得る。開く際は `FILE_FLAG_OPEN_NO_RECALL` を付ける。
  （プレースホルダ属性が本ツールのプロセスからどう見えるかは Phase 0 で実機検証する。）

共通:
- スキップは結果 JSON の `skipped[]`（理由コード `network-fs` / `automount` / `cloud-placeholder` / `unknown-fs` / `foreign-mount-namespace` 等）とログの両方に記録。
- 通常ファイル以外（FIFO、ソケット、デバイス）は開かない。開いた後はハンドルに対する `fstat` で再確認。
- **出力先・ログ先がネットワーク FS の場合は起動時にエラーで拒否**（書き込みが通信になるため）。出力先・ログ先自身はスキャン対象から自動除外。
- **本ツールの実行ファイル自体がネットワーク FS 上にある場合**（共有フォルダからの直接実行）は、実行中の読み込みがカーネルによる通信になる。既定では起動を拒否し、ローカルにコピーして実行するよう案内する。
- 実装での補足: Linux でマウント表が読めなければ起動を拒否する。Linux 以外の unix（macOS など。開発用）では、マウント表なしで、警告を記録して続行する。擬似 FS のスキップには理由コード `pseudo-fs` を使う。

### 4.4 暗黙の通信が起き得る処理と対応

| 処理 | 対応 |
|---|---|
| 証明書チェーン検証（AIA/CRL/OCSP 取得） | OS や標準ライブラリの検証 API を呼ばない。チェーンはローカルで見つかった証明書同士を Subject/Issuer と SKI/AKI の突き合わせで「関連付ける」だけ（信頼性判断はしない）。【未実装】証明書同士の関連付けは実装していない（検証 API を呼ばないことは守っている） |
| XML の外部実体・DTD・XInclude | `encoding/xml` は解決しない。XInclude 等も実装しない |
| 名前解決 | 設定中のホスト名は文字列として扱うのみ。UID→ユーザー名、SID→アカウント名の変換をしない |
| Windows 証明書ストア API | 【未実装】CryptoAPI のチェーン構築を使わず、レジストリ上のストア実体を直接パース |
| リモートレジストリ | 【未実装】（レジストリを読まない）ローカルハイブのみ。リモート接続 API を使わない |
| 設定ファイルの include | ローカルパスのみ `safefs` 経由で辿る。URL 形式・UNC は辿らず記録 |

### 4.5 秘密情報を出力しない仕組み

- **許可リスト方式の抽出**: 設定ファイルから取り出すのはルールで定義されたディレクティブだけ。未知のディレクティブの値は読み捨てる。
- **値の型と検証**: ルールは各ディレクティブに値の型（`cipher-list`, `protocol-list`, `curve-list`, `path`, `int`, `bool`, `enum`, `version`, `secret` …）を宣言する。出力前に型ごとのバリデータ（文字種・長さ・カタログ照合）を通し、通らない値は出力しない。自由文字列をそのまま出す型は設けない。
  版文字列など**正規表現で捕捉した値にも同じ検証**をかける。
- **カタログにないアルゴリズム名**: 棚卸し漏れを可視化するため記録するが、文字種・長さの制限（英数字と一部記号、64 文字以内）を満たす場合のみ名前を出す。満たさない場合は「不明な値あり」と長さだけを記録する。
- **`secret` 型**: パスワード等は「設定されている／平文で記載されている」という事実のみ記録し、値は保持もしない。【未実装】`secret` 型はない。パスワードの項目は、ルールに載せず、読み捨てている（「設定されている」という事実も記録しない）。実際の型は `algorithm-list` / `cipher-string` / `colon-list` / `flag` / `int` / `int-list` / `listen` / `path` / `words`。
- **秘密鍵**: 形式・アルゴリズム・鍵長・暗号化有無と、鍵ファイルに含まれる**公開成分**から計算した公開鍵フィンガープリント（証明書との対応付け用）のみ。
  秘密成分やファイル内容全体のハッシュは計算しない（照合オラクルになるため）。公開成分が得られない鍵（暗号化された鍵等）の ID は、内容ではなく場所（デバイス・inode・パス）から作る。
- **プロセス情報**: 読まない（`/proc/<pid>/` の `exe`・`maps`・`environ`・`cmdline`・`mem` のいずれも）。明示的に指定したときだけ、実行ファイルとライブラリのパスを読み、判断の材料にする機能は未実装で、最も優先度の低い将来のタスクとしている（当初の案は付録 A.4）。その場合も、`environ`・`cmdline`・`mem` など秘密を含み得るものは読まない。
- **パーサのエラー**: エラーメッセージに入力の断片が含まれ得るため、ログには種別と位置のみを記録する。
- **ログ**: 同じ規則に従う。ファイル由来の文字列は制御文字をエスケープ（ログ偽装対策）。
- **外部ルールの信頼境界**: 上記の検証があっても、ルールは「どのファイルのどの値を読むか」を決めるため、外部ルールを書ける人は本ツールの実行権限で読める情報の一部を出力に導ける。
  外部ルールは**バイナリと同等に信頼できるものだけを使う**前提とし、ルールディレクトリ・全ファイル・親ディレクトリが他ユーザー書き込み可、またはシンボリックリンクを含む場合は読み込みを拒否する。
  ルールが参照できるパスの種別もスキーマで制限する。
- ファイルパス、証明書の Subject/SAN 等は秘密ではないが機微情報であり、出力全体を機密として扱う（4.6）。仮名化オプションは将来検討。
- **キーストアのパスワード**: パスワードを使ってキーストアを開く機能は実装しない。設定ファイルに書かれたパスワードも、既定値（`changeit` 等）も使わない。

### 4.6 出力ファイルの保護

- Linux: ディレクトリ `0700`、ファイル `0600`。`O_EXCL|O_NOFOLLOW` で新規作成し、`.partial` からの確定は既存ファイルを上書きしない方法（`renameat2(RENAME_NOREPLACE)` または `link`）で行う。
- Windows: 【未実装】Windows では、この実装と実機での確認が済むまで、出力の書き込みそのものを拒否する（`scan`・`convert`・`report`・`rules export` は使えない）。設計は次のとおり: **作成時に**セキュリティ記述子を渡し、継承を切った DACL（実行ユーザーの SID のみ許可）と所有者を確定する（作成後に設定すると、その間は既定の権限で読めてしまうため）。
- 出力先ディレクトリが他ユーザー書き込み可の場合は拒否する。
- HTML レポート・CBOM・CSV・ログも同じ扱い。

### 4.7 ツール自身がバックドアにならないために

- 通信・子プロセス起動・動的コード読み込み（プラグイン、スクリプト実行）の機能を持たない。ルールは**純粋なデータ**（表と正規表現）で、任意コードを表現できない。
- 特権を要求・昇格しない。setuid での実行は拒否（【未実装】setuid で起動されたことの検出と拒否は実装していない）。Windows のバックアップ特権等で ACL を迂回しない。権限がなければ記録して先へ進む。
- 外部ルールの扱いは 4.5 のとおり。使用したルールセットの SHA-256 と日付を結果に記録。
- すべてのパーサは入力を敵対的とみなす: サイズ・ネスト深さ・展開率（ZIP 爆弾）の上限、ファイル単位の panic 回復（【未実装】パーサが panic すると、スキャン全体が止まる）、Go 標準のファジングテスト。
- HTML レポートは外部リソース参照ゼロ（CDN・Web フォントなし）、CSP メタタグで外部通信を禁止、埋め込みデータは文脈に応じてエスケープ（ファイルパスや証明書の Subject は攻撃者が制御し得るため）。
- CSV は数式インジェクション対策（`=`,`+`,`-`,`@` 始まりのセルを無害化）。
- 配布物: 再現可能ビルド（`-trimpath`、依存固定）、チェックサム。ツール自身の SBOM と、署名付きリリースは【未実装】。

---

## 5. スキャン対象と方式

### 5.1 コレクタ一覧

| コレクタ（実装での名前） | 対象 |
|---|---|
| `osconf` | OS 全体の暗号設定（crypto-policies、FIPS モード、`openssl.cnf`） |
| `pkgs` | パッケージ管理情報（dpkg、rpm）から、暗号ライブラリとアプリの版 |
| `bins` | ルールにあるアプリの本体がリンクしている暗号ライブラリ |
| `apps` | サーバーアプリケーションの設定と実効値（JDK、Tomcat、Spring Boot を含む） |
| `fscrawl` | 探索起点配下の証明書・鍵・キーストアファイル（証明書ストアの名前は、ルールで付ける） |
| `jars` | 探索起点配下の JAR に同梱された暗号ライブラリ |

コレクタは常にすべて実行する（選択の指定は【未実装】）。以下の節の見出しにある `ospolicy`・`certstore`・`binary` は、設計時の名前。

### 5.2 OS の暗号設定（`ospolicy`）

Linux:
- システム全体の暗号ポリシー: `/etc/crypto-policies/config`、`state/current`（RHEL 8+ 系）。`back-ends/` の下は、Java の分（`java.config`）を `apps` で読み、OpenSSL の分は `openssl.cnf` の `.include` を辿って読む
- FIPS モード: `/proc/sys/crypto/fips_enabled`
- OpenSSL 設定: `openssl.cnf`（ディストリごとの場所、`.include` をローカルに限り追跡）
- 【未実装】GnuTLS / NSS / libssh のシステム設定、`krb5.conf`（許可暗号種別）
- SSH: `sshd_config`（`Include`、`*.d` ディレクトリ含む。`apps` で扱う）。`ssh_config`（クライアント側）は【未実装】
- Java: 検出した各 JDK/JRE の `java.security`（無効化アルゴリズム等。`apps` で扱う）
- 【未実装】パスワードハッシュ方式: `login.defs`、PAM 設定（`/etc/shadow` は読まない。9章 C）

Windows（【未実装】。主にレジストリのローカルハイブから読取。64bit と WOW6432Node の両方を見る。OpenSSH for Windows や IIS はファイル）:
- Schannel: プロトコル、暗号、ハッシュ、鍵交換の有効/無効、暗号スイート順序（ポリシー／ローカル）、楕円曲線順序
- FIPS ポリシー、.NET Framework の強力な暗号設定（`SchUseStrongCrypto`、`SystemDefaultTlsVersions`）
- Kerberos 暗号種別、NTLM 互換レベル、RDP セキュリティ層、WinRM、OpenSSH for Windows の設定
- HTTP.sys の SSL バインド情報（レジストリ上の形式は非公開のため Phase 2 冒頭で調査。読めない場合は IIS の設定ファイルからの取得に留める）

どちらの OS も、「未設定のときの既定値」を OS バージョン／ビルド別の表としてルールに持ち、未設定項目を補完する（層: `os-default`）。
【実装と違う】OS の版ごとの既定値表は持たない。既定値は、アプリとライブラリのパッケージ版ごとの表（`rules/defaults/`、`rules/java/`）として持ち、出典を付けている。

### 5.3 サーバーアプリケーション（`apps`）

アプリは無数にあるため、**アプリごとのコードを書かず「アプリプロファイル」（ルール定義）で追加できる**構造にする。
【実装と違う】ルール（`rules/apps/*.yaml`）が持つのは、項目の名前と型、設定ファイルの場所、ユニット、パッケージの対応まで。設定の文法、継承、実効値の求め方は、
アプリごとの Go のコード（`internal/collect/apps/*.go`）にある。ルールだけで新しいアプリを足すことはできない。

処理の流れ:
1. **発見**: 既定の設定パスと、サービス定義（systemd ユニットの `ExecStart`・`Environment=`・`EnvironmentFile=`、Windows サービスの `ImagePath`【未実装】）から、インスタンス（実行ファイル＋設定ファイル）を特定。
   サービス定義に書かれた設定ファイル指定の引数や暗号関連の環境変数（`OPENSSL_CONF` 等、許可リストの名前のみ）はここから得る（稼働プロセスの `environ`・`cmdline` は読まない）。
   【未実装】`--process-info` 指定時のみ、Linux で稼働プロセスの `/proc/<pid>/exe` も使う（自プロセスと同じマウント名前空間のものに限る）。
2. **バージョン特定**（外部コマンドを実行しない）:
   - パッケージ管理情報: dpkg の status ファイル、**rpm DB**（RHEL 8 は Berkeley DB、RHEL 9 は SQLite。読み取り専用の最小リーダを実装。稼働中 DB をロックなしで読むため、ヘッダ検証と再試行を行う）。
     RHEL は修正をバックポートするため上流の版番号だけでは既定値を特定できない。**「ディストリ＋パッケージのリリース」を既定値表のキーに含める**。
   - 実行ファイル内の版文字列（例: `nginx/1.20.1`）、PE のバージョンリソース（パッケージ管理外のインストール向け。【未実装】）
   - 特定できない場合は `unknown` とし、既定値解決の信頼度を下げる
3. **リンクしている暗号ライブラリの特定**:
   - 既定: ELF の `DT_NEEDED` を RPATH/RUNPATH・`ld.so.cache`・標準探索パスで解決。PE はインポート表と同ディレクトリの DLL（【未実装】）。実行時に `dlopen` されるモジュールは分からないため、その旨を信頼度に反映する。
   - 【未実装】`--process-info` 指定時: `/proc/<pid>/maps` から実際にロードされているライブラリを得る（`dlopen` されたモジュールも分かる。削除済みファイルの表示は「更新後に再起動されておらず旧ライブラリで稼働中」を意味する）。
   - ライブラリ内の版文字列とパッケージ情報から版を特定。
4. **設定のパース**: 文法パーサは有限個をコードで実装（nginx 系ブロック、Apache 系、INI、key=value、sshd 系、XML、YAML、JSON、Java properties、postfix 系）。プロファイルが使う文法と include 規則を指定。
5. **抽出**: プロファイルが定義するディレクティブを取得。スコープと継承の規則はアプリごとに異なるため、単純なものはデータで、複雑なものは解決フック（5.4）で扱う。
6. **実効値解決**（5.4）。

外部コマンドを実行しない理由: root で任意のバイナリを起動することになり（PATH 汚染・改ざんバイナリのリスク）、負荷と副作用が読めず、「読み取りで完結」の原則に反するため。代償として版特定の精度が落ちる場面があるが、その場合は不確かさを明示する。

対応しているアプリ（2026-11-14 時点。`rules/apps/`）: OpenSSH（サーバー）、nginx、Apache httpd、Postfix、Dovecot、HAProxy、MySQL / MariaDB、PostgreSQL、stunnel、
JDK（OpenJDK）、Tomcat、Spring Boot。Java アプリの起動の定義として、systemd のユニットと supervisord のプログラムも読む。
【未実装】当初の一覧にあった IIS、OpenVPN、strongSwan / Libreswan、vsftpd、OpenLDAP（今後の順番は 12 章）。

### 5.4 実効値の解決

要件は「アプリの設定 ＞ OS の暗号ポリシー ＞ ライブラリのデフォルト」の順での解決を求めている。これを基本形としつつ、
現実には次のような例があるため、**単純な「最初に見つかった層を採用」ではなく、層ごとの演算を合成するモデル**とする。

- 層は値を「上書き」するとは限らず、「制限」（上限・下限・積集合）として働くことがある。例: アプリが暗号スイート文字列を明示しても、OS ポリシー由来のセキュリティレベルが別経路でそれを絞る。
- アプリは未記載の項目にも自身の既定値をライブラリへ明示的に設定することがある（nginx の `ssl_protocols` 等）。この場合「未記載＝OS ポリシーに従う」にはならない。
- 順序が逆転する例がある。RHEL 8 の sshd は OS ポリシーがコマンドライン引数として渡され、`sshd_config` の記載より優先される（RHEL 9 では仕組みが変わる）。

モデル:
- 層: `app-config`（明記）/ `app-default`（アプリの既定値。版・ディストリ別）/ `os-policy` / `library-default` / `os-default`。
- 各層は、パラメータごとに演算の種類を持つ: `override`（置換）/ `restrict`（制限）/ `modify`（追加・削除。sshd の `+`/`-`/`^` 等）。
- 層の適用順と演算は**アプリプロファイル側で宣言**する（ディストリ・版の条件付き）。既定は要件の順。【実装と違う】層の順と演算は、アプリごとのコードで決めている（ルールでは宣言しない）。
- アプリ固有の込み入った規則（設定の継承・マージ、sshd の先勝ちと `Match`、Apache の vhost マージ等）は、プロファイルから名前で参照する**解決フック**（Go コード。有限個）で実装する。
  「アプリごとのコードを一切書かない」ことは目指さず、「単純なアプリはデータだけで追加でき、複雑なアプリは小さなフックを足す」構造とする。
- 出力には、合成結果（実効値）に加えて**各層の生の値を事実として必ず残す**。合成規則に誤りがあっても、後から検証・再解決できる。
- OpenSSL の暗号文字列（`HIGH:!aNULL:!MD5`、`PROFILE=SYSTEM`、`@SECLEVEL=2` 等）は版別・ディストリ別の暗号スイート表に対して評価し、具体的なスイート一覧に展開する。TLS 1.3 のスイートは別管理として扱う。
- 各値に `state`（`configured` / `effective` / `default`）と `confidence` を付ける。【実装と違う】実装では、記載 1 つずつを `settings[]` に、合成した結果を `effective_values[]`（`status` は `resolved` / `unresolved`、`confidence`、求めた手順 `steps`）に分けて記録する（7.2）。版が不明、表にない版、ビルド時オプションやディストリ独自パッチに依存する等で解決しきれない場合は `unresolved` と理由を記録し、推測で埋めない。

正しさの検証（開発時のみ。ツール本体は外部コマンドを実行しない）:
CI 上の各ディストリのコンテナ内で `sshd -T`、`openssl ciphers -V`、実際のハンドシェイクによる列挙を行って正解データを採取し、kagiya の解決結果と突き合わせる。
版別スイート表もこの仕組みで実物から生成する。この突き合わせが通ることを Phase 1c の完了条件とする。
【実装と違う】突き合わせ（差分テスト）は CI ではなく、検証ラボ（`lab/`。リポジトリには含めない）で手動で行っている。CI が確かめるのは安全策（`ci/verify-linux.sh`）とテストまで。結果は records.md に記録する。

### 5.5 証明書・鍵・キーストア（`certstore`, `fscrawl`）

OS 標準ストア:
- Linux: `/etc/ssl/certs`、`/etc/pki/tls`、`/etc/pki/ca-trust`、`/usr/local/share/ca-certificates` 等（ディストリ別にルール定義）
- Windows: 【未実装】システム証明書ストアの実体を直接パースする。ローカルマシン・グループポリシー・Enterprise の各ストア（レジストリ）、実行ユーザーのストア（レジストリおよび `%APPDATA%\Microsoft\SystemCertificates` 配下のファイル）、
  ロード済みのサービスアカウントのハイブ、サービス別ストア。物理位置の一覧はルール（`os/windows.yaml`）で定義する。秘密鍵の有無はプロパティ（プロバイダ名・コンテナ名）から判定

アプリ固有ストア:
- Java: `cacerts`、JKS / JCEKS / PKCS#12 / BKS / UBER / BCFKS
- NSS DB（`cert9.db` 等）: 存在と場所を記録（内容のパースは Phase 6 で検討）。【未実装】
- アプリ同梱 CA バンドル（`cacert.pem`、`certifi` 等）、アプリ設定が参照する証明書・鍵ファイル

ファイル探索:
- 拡張子とマジック（PEM ヘッダ、DER 構造、キーストアのマジック）で判定。対象: X.509 証明書、CSR、各形式の秘密鍵・公開鍵（PKCS#1/8、SEC1、OpenSSH）、キーストア。CRL、PuTTY PPK、PGP 鍵は【未実装】。
- SSH の `authorized_keys`・`known_hosts`・ホスト鍵も対象。Kerberos keytab の暗号種別は【未実装】。
- 既定の探索起点 — Linux: `/etc`, `/opt`, `/usr/local`, `/srv`, `/var/www`, `/root`（`/home` は巨大・自動マウント・個人ファイルの懸念から既定では含めない）。Windows（【未実装】）: `%ProgramData%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `C:\inetpub`。`--roots /` 等でローカル FS 全体も指定可能（9章の相談事項）。

パスワード保護されたコンテナ（PKCS#12 等）は、既定ではパスワードなしで読める範囲（外側構造、MAC・PBE アルゴリズム、反復回数）を記録。JKS は証明書エントリをパスワードなしで読める。
近年の Java の既定は PKCS#12 で証明書も暗号化されるため、中身が見えないストアが多くなる。パスワードは一切使わない方針（9章 A）のため、
その場合は「暗号化されており内容未確認」のキーストア資産として記録し、レポートで**未確認の範囲**として明示する。設定ファイルが別途参照する証明書ファイル（PEM 等）は通常どおり読む。

### 5.6 バイナリと JAR（`binary`）

扱うのは「どの暗号ライブラリの、どの版があるか」まで。「どの API を参照しているか」「実際にどう呼ばれるか」は扱わない（付録 A.2）。
逆アセンブル・逆コンパイルは行わず、ファイル形式上のメタデータと名前だけを読む。

| 対象 | 読むもの |
|---|---|
| ELF（ルールにあるアプリの本体と、定義したモジュール） | 動的セクション（`DT_NEEDED`、探索パス）から、リンクしている暗号ライブラリの実体を特定する。版は、パッケージ情報と、ライブラリに埋め込まれた版文字列から |
| JAR / WAR / EAR（探索起点配下） | 中身の一覧（ファイル名）だけ。同梱ライブラリの置き場（`BOOT-INF/lib/`、`WEB-INF/lib/`、`lib/`）にある JAR の名前から、暗号ライブラリ（Bouncy Castle、Conscrypt、Netty の tcnative、組み込みの Tomcat）と版を特定する。入れ子の JAR も、クラスファイルも開かない |
| 決まった名前の設定ファイル（JAR の中） | Spring Boot の `application.properties` / `.yml` など、ルールで定めたものだけ。取り出すのは許可した項目だけで、パスワードの項目は許可しない（読み方の条件は records.md の 6 章） |

JAR は、上限つきで読む（全体の大きさ、エントリの数、名前の長さ、読むエントリの大きさ、圧縮の倍率）。ディスクには展開しない。

### 5.7 共通事項

- 読み取り権限がない場合: 理由コード `permission-denied` でログと `skipped[]` に記録して継続。
- 除外: `--exclude`（グロブ）。除外でスキップしたことも記録。`--exclude-from` は【未実装】。
- 上限超過（サイズ、時間、ネスト）によるスキップも記録。結果 JSON に網羅性サマリ（走査数・スキップ数・理由別内訳）を持たせ、**「見ていないもの」が分かる**ようにする。

---

## 6. 負荷を抑える設計

優先度を下げるだけでは不十分（空きコアがあれば 1 コアを使い切り、監視の閾値に触れ得る）なので、**優先度の低下**と**自前の流量制限**を併用する。

優先度:
- Linux: nice 19 と I/O 優先度 idle を設定。これらはスレッド単位の属性で、Go は複数の OS スレッドを持つため、全スレッドに適用する仕組み（`syscall.AllThreadsSyscall`）を使い、
  適用後に全スレッドの nice 値を `/proc/self/task/*/stat` で確認して `meta.hardening` に記録する。I/O 優先度は I/O スケジューラによっては効かないため補助と位置づける。
- Windows（【未実装】）: `IDLE_PRIORITY_CLASS` ＋ I/O 優先度 Low。バックグラウンドモード（`PROCESS_MODE_BACKGROUND_BEGIN`）はワーキングセットが極端に制限され逆に遅くなる報告があるため使わない。
  Job オブジェクトで CPU レート上限とメモリのハード上限を設定する。
- 失敗時は警告を記録して継続。

流量制限（既定で有効。数値は Phase 0 の負荷試験で確定し、すべてオプションで変更可）:

| 項目 | 既定値（暫定） |
|---|---|
| 並行度 | 1（固定。`--workers` は【未実装】） |
| CPU 使用率の上限 `--cpu-limit`（処理と休止の比率で制御） | 1 コアの 25% |
| 読み取り速度の上限 `--io-limit` | 20 MiB/秒 |
| メモリ上限（Go のソフトリミット。Windows は Job のハード上限も） | 512 MiB【未実装】（上限は設定していない） |
| 1ファイルの読み取り上限 `--max-file-size` | 64 MiB（超えるファイルは読まずにスキップして記録する。先頭だけを読む扱いは【未実装】） |
| 実行時間上限 `--max-duration` | なし（指定推奨） |

その他:
- 読む量を最小にする: 種別判定は先頭数 KB、ELF/PE は必要なヘッダ・表のみ。【実装と違う】探索で見つけた証明書・鍵の候補は、上限以下ならファイル全体を読む。必要な部分だけを読むのは、ELF と JAR。
- 探索は既定で限定された起点のみ。同一 inode の重複排除（【未実装】）。
- ファイルをロックしない: Windows では読み取り・書き込み・削除をすべて共有許可で開く（標準 API は削除共有を付けないため自前で開く）。アプリのログローテーションや設定差し替えを妨げない。
- Linux では可能な場合 `O_NOATIME`（所有者または特権が必要。不可なら通常オープンに戻し件数を記録）。【未実装】
- `fadvise(DONTNEED)` は本番アプリのキャッシュを追い出し得るので使わない。大量読取によるキャッシュへの影響は流量制限と読取量の最小化で抑える。
- 割り込み（SIGINT/SIGTERM、Ctrl+C）で安全に停止し、途中結果を「未完了」と明記して出力。
- 本ツールの制御外の影響（アンチウイルスのリアルタイムスキャン負荷、ファイルアクセス監査ログの増加、EDR による検知）は利用者向け文書に明記し、
  事前申請に使える「読み取り対象一覧」（`--dry-run` の出力）を提供する（【未実装】）。

---

## 7. データモデル

### 7.1 入力

| 入力 | 内容 |
|---|---|
| コマンドライン引数 | 3.2 |
| ルール定義 | 内包（既定）または `--rules DIR`（7.3） |
| ローカルシステム | ファイル、レジストリ（Windows）、`/proc`・`/sys` の特定項目（Linux） |
| 結果 JSON | `convert` / `report` の入力 |

### 7.2 出力（独自 JSON スキーマ `kagiya-inventory`。Phase 3 完了まで `v0`）

考え方:
- **事実と評価の分離**: スキャン結果は「何がどこにあるか」という事実を主とする。危殆化・量子耐性の評価はカタログに基づく付加情報で、
  `report` / `convert` 実行時に**その時点のルールで再評価**できる。新たな危殆化が判明しても再スキャンなしで過去の結果を評価し直せる。
- **資産と出現の分離**: 同じ証明書・同じアルゴリズムが多数の場所に現れるため、一意な「資産」と、場所・文脈を持つ「出現」に分ける（CycloneDX CBOM の component / occurrence と対応が取りやすい）。
- **安定 ID**: スキャン間の差分（追加・消滅・変化）を取れるようにする。出現の ID は「資産・ルール・正規化した場所（行番号を含めない）・スコープ・用途」のハッシュ＋同一キー内の序数。
- **生の名前の保存**: すべての出現に、見つけたままの名前と命名体系（`jca` / `openssl` / `oid` / `ssh` / `iana` …）を保存する。カタログの ID が将来改名・分割されても、過去の結果を再正規化・再評価できる。
- **順序を持つ設定の表現**: 暗号スイート一覧のように順序に意味がある設定は `settings[]`（サービス × スコープ × 項目）として、順序付きの資産参照と解決チェーンを持たせる。個々の出現に分解して順序を失わない。
- **ホストの同一性**: ホスト名だけでは「同一ホストの別時点」と「別ホスト」を区別できないため、machine-id / MachineGuid の鍵付きハッシュを `host.id` とする（生の値は出さない）。【未実装】`host.id` はない（ホスト名だけ）。
- **パスの表現**: UTF-8 として不正なファイル名（EUC-JP・Shift_JIS のファイル名等）は、損失のないエスケープ表記で記録する。（実装での扱いは未確認）

【実装と違う】下の JSON は設計時の案で、実際の形とは違う。正は `internal/model/model.go`。主な違い:

- 最上位の項目は `schema`、`meta`、`assets`、`occurrences`、`package_databases`、`packages`、`os_settings`、`services`、`settings`、`effective_values`、`components`、`assessment`、`skipped`、`coverage`。`errors` はない。
- `meta`: `host.id`・`host.kernel`・`tool.build`・`invocation.source_dirs`・`invocation.collectors`・`hardening.landlock` はない。ディストリは `host.distribution`（`id`、`version_id`、`name`）。
  ほかに `incomplete_reason`、`warnings`、`hardening.io_priority`・`core_dump_disabled`・`notes` がある。
- 資産の型は `algorithm` / `certificate` / `private-key` / `public-key` / `csr` / `keystore`。ライブラリは `components[]` に、プロトコルや暗号スイートは `effective_values[].values` に文字列で持つ（資産にしない）。
  証明書の `key_usage`・`san`・`issuer_ref` はない。
- `occurrences[]` は、ファイルとして見つかった資産の場所だけ（`collector` は `fscrawl`、`state` は `present`）。`service`・`endpoint`・`usage`・`setting`・`evidence` はない。
  `location` は `kind`・`path`・`index`・`container`（行・列は持たない）。
- `services[]` は `id`・`app`・`component`・`config_files`・`activity`（利用の確からしさ。11 章）・`notes`。`version`・`binary`・`crypto_backend`・`endpoints` はない。
- `settings[]` は、設定ファイルの記載 1 つにつき 1 件（`parameter`、`direction`、`scope`、`layer`、`values`、`location` など）。層を合成した結果は `effective_values[]`
  （`status`: `resolved` / `unresolved`、`values`、`confidence`、`reason`、`notes`、求めた手順 `steps[]`）に分けて持つ。
- `assessment` は `assets` と `values` に分かれ、判定は `quantum`・`classical`・`rules`。`references` はない。
- `coverage` は `files_examined`、`dirs_examined`、`symlinks_not_followed`、`special_files_not_opened`、`bytes_read`、`skipped_by_reason`、`skipped_list_truncated`。

```jsonc
{
  "schema": "kagiya-inventory/v0",
  "meta": {
    "scan_id": "…", "started_at": "…", "finished_at": "…", "completed": true,
    "tool": { "version": "…", "build": "…" },
    "rules": { "source": "builtin|external", "version": "…", "sha256": "…" },
    "host": { "id": "…", "hostname": "…", "os": "linux", "distro": "rhel", "os_version": "9.4",
              "kernel": "…", "arch": "amd64" },
    "labels": { "system": "勘定系", "owner": "…" },
    "invocation": { "roots": ["…"], "source_dirs": ["…"], "excludes": ["…"], "collectors": ["…"] },
    "privilege": { "elevated": true },
    "hardening": { "priority_lowered": true, "seccomp": "applied", "landlock": "unsupported" }
  },

  "assets": [
    { "id": "alg:aes-256-gcm", "type": "algorithm",
      "algorithm": { "family": "AES", "primitive": "aead", "mode": "GCM", "key_bits": 256 } },
    { "id": "cert:sha256:ab12…", "type": "certificate",
      "certificate": { "subject": "…", "issuer": "…", "serial": "…",
        "not_before": "…", "not_after": "…", "is_ca": false, "self_signed": false,
        "signature_algorithm": "alg:sha256-with-rsa",
        "public_key": { "algorithm": "alg:rsa-2048", "fingerprint_sha256": "…" },
        "key_usage": ["…"], "san": ["…"], "issuer_ref": "cert:sha256:…" } },
    { "id": "key:sha256:cd34…", "type": "private-key",
      "key": { "algorithm": "alg:rsa-2048", "format": "pkcs8", "encrypted": false,
               "public_fingerprint_sha256": "…" } },
    { "id": "lib:openssl@3.0.7", "type": "library", "library": { "name": "openssl", "version": "3.0.7" } },
    { "id": "proto:tls1.2", "type": "protocol", "protocol": { "name": "TLS", "version": "1.2" } }
  ],

  "services": [
    { "id": "svc:nginx:/etc/nginx/nginx.conf", "app": "nginx",
      "version": { "value": "1.20.1", "source": "binary-string", "confidence": "high" },
      "binary": "/usr/sbin/nginx", "config_files": ["…"],
      "crypto_backend": { "library": "lib:openssl@3.0.7" },
      "endpoints": [ { "scope": "server example.co.jp:443", "usage": "tls-server" } ] }
  ],

  "occurrences": [
    { "id": "occ:…", "asset": "proto:tls1.2", "collector": "apps",
      "service": "svc:nginx:/etc/nginx/nginx.conf", "endpoint": 0,
      "usage": "tls-server",
      "state": "effective",            // configured | effective | default | capability | reference
      "confidence": "high",
      "setting": "set:…",              // 順序・層別の値・解決過程は settings[] 側に持つ
      "evidence": { "rule": "apps/nginx#ssl_protocols" } },

    { "id": "occ:…", "asset": "alg:aes-128-ecb", "collector": "source", "usage": "encryption",
      "state": "reference", "confidence": "medium",
      "location": { "kind": "file", "path": "/src/app/Crypto.java", "line": 42, "column": 17 },
      "evidence": { "rule": "source/java/jca#cipher-getinstance",
                    "api": "javax.crypto.Cipher.getInstance", "spec": "AES",
                    "note": "モード未指定のためプロバイダ既定(ECB)と解釈" } }
  ],

  "settings": [                        // 順序付き・層別の値を持つ設定項目
    { "id": "set:…", "service": "svc:nginx:/etc/nginx/nginx.conf", "scope": "server example.co.jp:443",
      "parameter": "tls.cipher-suites", "state": "effective", "confidence": "medium",
      "effective": ["suite:TLS_AES_256_GCM_SHA384", "suite:ECDHE-RSA-AES256-GCM-SHA384"],
      "layers": [                      // 各層の生の値（事実）と、合成で果たした役割
        { "layer": "app-config",  "op": "override", "raw": "HIGH:!aNULL:!MD5",
          "location": { "kind": "file", "path": "/etc/nginx/nginx.conf", "line": 41 } },
        { "layer": "os-policy",   "op": "restrict", "raw": "@SECLEVEL=2", "source": "crypto-policies:DEFAULT" }
      ] }
  ],

  "assessment": {                      // スキャン時点の評価ポリシーによる評価のスナップショット（参考値）
    "policy": "default", "policy_version": "…",
    "by_asset": { "alg:rsa-2048": { "quantum": "vulnerable", "classical": "acceptable",
                                    "references": ["NIST IR 8547", "CRYPTREC"] } }
  },

  "skipped": [ { "path": "/mnt/share", "reason": "network-fs", "detail": "nfs4" },
               { "path": "/etc/ssl/private", "reason": "permission-denied" } ],
  "coverage": { "files_examined": 0, "skipped_by_reason": { "network-fs": 1 }, "collectors": { "apps": "ok" } },
  "errors": [ ]
}
```

- 資産の型（設計時の案。実際は上の「主な違い」）: `algorithm` / `cipher-suite` / `certificate` / `private-key` / `public-key` / `keystore`（形式、保護方式、反復回数、エントリ数）/ `library` / `protocol`。
- `location.kind`: `file` / `registry` / `certstore` / `archive-entry`（`a.war!/WEB-INF/lib/b.jar!/X.class`）等。
- **評価**: 危殆化・量子耐性の判定は用途と基準で変わる（例: SHA-1 は署名用途と HMAC 用途で扱いが異なる）ため、カタログの固定属性ではなく
  **評価ポリシー**（「資産・パラメータ・用途」の条件 → 判定・期限・根拠文書。CRYPTREC、NIST 等の複数プロファイル）としてルールに持つ。
  結果 JSON 内の `assessment` はスキャン時点の参考値で、`report` / `convert` は実行時のポリシー（`--policy`、`--rules`）で再評価し、使用したポリシーを出力に記録する。
  【実装と違う】再評価するのは `report` だけ。`convert` は結果の中の `assessment` をそのまま使う（CSV には評価の列がない）。
- 大規模結果に備えストリーミングで書き出す（【未実装】一括で書き出している）。`skipped` が膨大な場合は理由別件数を必ず保持し、個別一覧は上限を設けて全件をログへ。
- JSON Schema をリポジトリに同梱し、`schema` の版で互換性を管理する。【未実装】（JSON Schema はない）

変換:
- **CBOM**: CycloneDX JSON（1.6 で固定。`--cbom-version` は【未実装】）。`cryptographic-asset` コンポーネント＋ `evidence.occurrences`、アプリ→ライブラリ→アルゴリズムの関係は `dependencies` で表す。
  CycloneDX の出現は状態（設定済み／可能性のみ）や信頼度を持てないため、区別が必要な情報は `properties` に落とす。解決チェーン等は省略。
  カタログには CBOM の属性（パラメータセット、暗号機能、セキュリティレベル等）を持たせ、公式 JSON Schema での検証をテストに含める。
- **CSV**: 出現1件＝1行に平坦化（ホスト、資産種別、アルゴリズム、鍵長、用途、状態、場所、アプリ、評価 …）。Excel での文字化けを避けるため UTF-8 BOM 付き（`--no-bom` で BOM なし。CP932 への切替は【未実装】）。

### 7.3 検出ルール

- 形式は YAML。厳格に読み込む（未知のキーは拒否、値は文字列として扱い `1.20` が数値 `1.2` に化ける類の罠を避ける）。内包ルールは `go:embed`。
- YAML パーサの選定条件: 保守が続いていること、`net`・`os/exec` に依存しないこと、**エイリアス展開に上限があること**（少数のアンカーを多重参照して巨大なデータに膨らませる攻撃への耐性）。
  加えて本ツール側でも、ルールファイルのサイズ・ネスト深さ・展開後のノード数に上限を設け、ルールでアンカー／エイリアスを使う必要がないため**エイリアス自体を拒否**する。
  上限が効くことは、展開爆発を仕込んだルールファイルを使うテストで確認する。
- `--rules DIR` 指定時は既定で**内包ルールを使わず DIR のみ**を使う（挙動が一意）。`rules export` → 編集 → `--rules` の流れ。
  社内アプリのプロファイルを少数足したいだけの場合のために `--rules-mode overlay`（内包ルールに追加・上書き）も用意する。
  外部ルールの基準版がバイナリ内包版より古い場合は、ログ・結果・レポートに警告を残す。
  【未実装】`--rules-mode overlay` と、外部ルールが古い場合の警告。
- 版の比較方式はプロファイルで宣言する（`semver` / `openssl`（`1.1.1k`）/ `openssh`（`9.6p1`）/ `rpm` / `dpkg`）。既定値表は「版」に加え「ディストリ・パッケージリリース」を条件にできる。
  【実装と違う】版の大小比較はしない。既定値表は、実測したパッケージ版との完全一致で引き、表にない版は、同じ系列・同じ上流版に限って補間する（確度を下げる）。
- 鍵長等の導出もデータで宣言する（RSA のモジュラス長、EC の曲線、固定値）。【実装と違う】鍵長の導出はパーサのコードにある。
- ルールは宣言的データのみ。照合に使う正規表現は線形時間のエンジンで評価される。
- 読み込み時に全体を検証（スキーマ、ID 重複、カタログ参照の解決）し、エラーがあれば起動を止める。

実際のファイル構成（`rules/`）:

| ファイル群 | 内容 |
|---|---|
| `manifest.yaml` | ルールの版と日付 |
| `catalog/algorithms.yaml` | 暗号カタログ: 正規 ID、種別、パラメータ、別名（OID、OpenSSL 名、SSH 名など） |
| `policies/default.yaml` | 評価ポリシー（7.2） |
| `ciphers/openssl.yaml`、`groups/openssl.yaml` | OpenSSL の暗号スイートと鍵交換のグループの表（パッケージ版ごと。出典つき） |
| `libraries/*.yaml` | 暗号ライブラリの識別（soname、パッケージ名、JAR のファイル名） |
| `os/packages.yaml`、`os/stores.yaml` | パッケージの役割の対応、標準の証明書ストアの場所 |
| `apps/*.yaml` | アプリの定義: 本体、パッケージ、設定ファイルの場所、ユニット、項目の名前と型（5.3）。出典（`sources`）は必須 |
| `defaults/*.yaml` | アプリの既定値（パッケージ版ごと。出典つき） |
| `java/*.yaml` | JDK・Tomcat・Spring Boot の表（版ごと。出典つき） |

【実装と違う】当初の案にあった `catalog/tls.yaml`、`os/linux.yaml`・`os/windows.yaml`（OS 設定の所在、ネットワーク FS の種別）、`source/<lang>/*.yaml`、`binary/*.yaml`、
`files.yaml`（ファイルの判定）はない。ファイルの判定とネットワーク FS の種別は、コードに持っている。

**新しい暗号の追加**は、`catalog/algorithms.yaml` に1エントリ（ID、別名、OID）を足せば証明書・設定・ソース・バイナリの各コレクタで名前として認識される。
TLS で使う場合は `catalog/tls.yaml`（コードポイント・スイート）、ライブラリの版別対応表、評価ポリシーにも追記が要るが、いずれもデータの変更でコードの変更は不要。
カタログにない名前に出会った場合は捨てずに未知のアルゴリズムとして記録し（出力条件は 4.5）、棚卸し漏れを可視化する。

例（設計時のイメージ。【実装と違う】実際の書式は `rules/apps/*.yaml` と `rules/defaults/*.yaml` を参照。既定値はアプリの定義と分けて持ち、`secret` 型と `source/` はない）:

```yaml
# catalog/algorithms.yaml
- id: ml-kem-768
  family: ML-KEM
  primitive: kem
  aliases: { oid: ["2.16.840.1.101.3.4.4.2"], openssl: ["ML-KEM-768", "MLKEM768"], jca: ["ML-KEM-768"] }
  references: ["FIPS 203"]

# apps/nginx.yaml
id: nginx
discover:
  binaries: ["nginx"]
  config_paths: { linux: ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"] }
  service_flags: { config: ["-c"] }      # サービス定義（ExecStart 等）の引数から設定ファイルを特定
version: { binary_string: 'nginx/(\d+\.\d+\.\d+)' }
grammar: nginx
backend: openssl
directives:
  - name: ssl_protocols
    type: protocol-list
    scopes: [http, server]
    defaults:
      - { versions: "<1.23.4",  value: "TLSv1 TLSv1.1 TLSv1.2" }
      - { versions: ">=1.23.4", value: "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3" }
  - name: ssl_ciphers
    type: cipher-list
    scopes: [http, server]
    defaults: [ { versions: "*", value: "HIGH:!aNULL:!MD5" } ]
  - name: ssl_certificate
    type: path
    role: certificate
  - name: ssl_password_file
    type: secret

# source/java/jca.yaml
- id: cipher-getinstance
  match: { call: "javax.crypto.Cipher.getInstance", capture_arg: 0 }
  interpret: jca-transformation
  usage: encryption
```

（表中の既定値は例示。実際の値は各アプリの公式文書と実物で検証して定義する。）

### 7.4 HTML レポートと集約

主対象の規模は**数百〜数千ホスト**。全ホストの明細を1つの HTML に埋め込むことはできないため、集約を前提に設計する。

【実装と違う】いまの `report` は、結果 JSON を最大 200 個まで受け取り、「全体の集計」と「ホストごとの詳細」を 1 つの HTML にする（`kagiya report [--output-dir DIR] [--policy NAME] [--rules DIR] 入力...`）。
日本語で固定（`--lang` は【未実装】）。JavaScript は使わず（CSP で禁止）、開閉は `<details>` だけなので、絞り込み・検索・並べ替えは【未実装】。
`merge` と集約 JSON、データ量による表示の自動切り替え、ホストの時点間の差分も【未実装】。以下は当初の設計。

- `kagiya report [-o DIR] [--lang ja|en] [--policy NAME] 入力...` → 単一 HTML（CSS/JS/データをすべて内包、外部参照なし）。入力は結果 JSON（複数可）または集約 JSON。
- `kagiya merge -o DIR 結果JSON...`（ディレクトリ指定可）→ 集約 JSON。結果ファイルを1つずつストリーミングで読み、メモリ使用量をホスト数に比例させない。
  集約 JSON 同士もさらに集約できる（部門ごとに集約 → 全社で集約、という持ち寄り運用を想定）。
- 集約の単位は「検出グループ」: （資産 × 用途 × 状態 × アプリ）ごとに、該当ホストの一覧と件数を持つ。構成の似たホストが多い大規模環境ではよく圧縮される。
  ホスト別には、要約（リスク区分別件数、OS、ラベル、スキャン日時、網羅性、ルール版）を持つ。

表示は入力に応じて切り替える:

| 入力 | 表示 |
|---|---|
| 1ホスト | サマリ（量子脆弱・非推奨・要確認の件数）、アルゴリズム別・用途別の内訳、サービス別の実効設定と各層の値、証明書一覧と有効期限、ソース／バイナリの検出一覧、**スキャンできなかった範囲**、絞り込み・検索 |
| 複数ホスト（明細を埋め込める規模） | 上記に加え、ホスト横断ビューとホスト別ドリルダウン |
| 多数ホスト／集約 JSON | 全体サマリ、ラベル別（システム・部門）の集計、ホスト × リスク区分の一覧（並べ替え・絞り込み）、アルゴリズムから利用ホストへの逆引き、証明書期限の全体分布、同一証明書・鍵の使い回し、古いルール／未完了スキャンのホスト一覧。個別ホストの明細は埋め込まず、そのホストの結果 JSON から個別レポートを作る運用とする |

- 明細を埋め込むか集約表示にするかは、データ量の上限で自動的に決め、どちらで表示しているかを画面に明示する。
- 同一ホストの異なる時点（`host.id` で判定）の差分・推移ビューは Phase 6。
- 評価はレポート生成時の評価ポリシーで再計算する。

### 7.5 ログ

- 既定 `./logs/`、`--log-dir` で変更。実行ごとに1ファイル（JSON Lines）。権限は出力と同じ。
- 記録内容: 起動条件、適用した安全策、スキップ（理由別、権限不足・上限超過・設定の問題を含む）、未完了の理由、終了サマリ。コレクタごとの開始・終了は記録していない。ログを書くのは `scan` だけ。
- 標準エラー出力には進捗と要約のみ。

---

## 8. 動作環境と互換性

| OS | 対象 | 考慮点 |
|---|---|---|
| RHEL 系 8 以降（互換ディストリ含む） | amd64 / arm64 | crypto-policies、FIPS モード、`/etc/pki` 配置、SELinux 下での権限拒否（記録して継続） |
| Ubuntu 16.04 以降（Debian 系） | amd64 / arm64 | crypto-policies なし（OpenSSL/GnuTLS 各設定とライブラリ既定で解決）、`/etc/ssl` 配置、版ごとの OpenSSL 系統差（1.0.2 / 1.1.x / 3.x） |
| その他 Linux | ベストエフォート | ディストリ判定は `/etc/os-release`。【実装と違う】汎用プロファイルはない。表にないディストリ・版では、既定値に頼る項目が「不明」になる |
| Windows Server 2016 以降、Windows 10 以降 | amd64 | 【未実装】ビルドはできるが、スキャン・変換・レポートは使えない（出力の保護が未実装のため、書き込みを拒否する）。配布もしていない。設計: ビルド番号別の Schannel 既定値、長いパス、管理者権限なしでの縮退動作 |

- 権限: 一般ユーザーでも動作し、読めないものは記録する。網羅性のためには root / 管理者での実行を推奨（文書に明記）。
- 実行制御の考慮: `noexec` マウント、RHEL の fapolicyd、Windows の WDAC / AppLocker、SELinux 下でのジョブ実行について、利用者向け文書で設置場所と許可設定を案内する。
- Windows コンソール（CP932）での文字化けを避けるため、標準エラー出力のメッセージは ASCII のみとする。
- OS・ディストリ・版の差異はコードの分岐ではなく、可能な限りルール（`os/*.yaml`）で表現する。

---

## 9. 設計上の主な判断

### 9.1 ユーザーに相談して決定した事項（2026-11-12）

| # | 論点 | 決定 |
|---|---|---|
| A | パスワード保護されたキーストア | **パスワードは一切使わない**（機能自体を実装しない）。暗号化されて読めない部分は「未確認」として明示 |
| D | 稼働プロセス情報の利用 | **既定では読まない**。`--process-info` 明示時のみ、Linux で `/proc/<pid>/exe` と `maps` だけを読む。`environ` 等の機微な情報を含むファイルは読まない（`cmdline` も同様に扱う）。【未実装】明示時に読む機能は、最も優先度の低い将来のタスク（1.3、付録 A.4） |
| F | 実効値解決の順序 | 要件の順を基本形とし、**現実の挙動が異なるアプリは現実の順で解決**する。各層の生の値も記録 |
| H | レポートの規模 | **数百〜数千ホスト**を主対象とする。集約（`merge`）と集約表示を v1 の必須機能とする。【未実装】（7.4） |

### 9.2 設計者の判断で決めた事項（異論があれば変更可能）

| # | 論点 | 本設計での既定 | 代替 |
|---|---|---|---|
| B | 既定のファイル探索範囲 | 5.5 の限定された起点（`/home` は含めない） | ローカル FS 全体を既定にする（網羅性↑・負荷↑） |
| C | `/etc/shadow` のハッシュ方式集計 | 読まない（機微なファイルを読まない方針 D に合わせる）。`login.defs`・PAM 設定から方式を得る（【未実装】） | オプションで方式の件数のみ集計 |
| E | 外部ルール指定時の動作 | 内包ルールを完全に置換（`--rules-mode overlay` で追加・上書きも可。overlay は【未実装】） | overlay を既定にする |
| G | 出力先・実行ファイルが共有フォルダ上の場合 | 拒否（ローカルに置く運用を案内） | 警告のみで許容 |
| I | 評価基準の既定 | CRYPTREC 暗号リストと NIST（SP 800-131A、IR 8547）を併記 | いずれか一方 |
| J | 対象外の旧 OS（RHEL 7、Windows Server 2012 R2 以前） | 対応しない（要件どおり） | — |
| K | コンテナイメージ層の解析 | v1 対象外 | 将来フェーズ |
| L | レポートの既定言語 | 日本語（`--lang en` で英語。英語は【未実装】） | 英語既定 |

### 9.3 当初の設計のうち、実装していないもの（2026-11-14 に実装と突き合わせ）

本文の該当箇所に【未実装】【実装と違う】を付けた。ここでは、まとめて一覧にする。「扱い」が「判断待ち」のものは、実装するか、設計から外すかを決めていない。

安全と負荷に関わるもの:

| 項目 | 設計の場所 | いまの状態 | 扱い |
|---|---|---|---|
| setuid で起動された場合の拒否 | 4.7 | 検出も拒否もしていない | 判断待ち |
| ファイル単位の panic 回復 | 4.7 | ない。パーサが panic するとスキャン全体が止まる（ファジングと上限で防いでいる） | 判断待ち |
| Go のトレースバック設定の固定、`GODEBUG` などの警告 | 3.2、4.2 | ない（コアダンプの無効化はある） | 判断待ち |
| メモリの上限（512 MiB） | 6 | 設定していない | 判断待ち |
| overlayfs の下の層、loop デバイスの元ファイルの判定 | 4.3 | overlayfs は無条件にローカル扱い | 判断待ち |
| 名前で開く経路（Opener）のハンドル相対化、`openat2` | 4.3 | 1 要素ずつ確かめた後にパスで開き、最後の要素だけ照合する | 判断待ち |
| ネットワーク FS の種別をルールで拡張 | 4.3、7.3 | コードに固定 | 判断待ち |
| ネットワーク名前空間を切り離した結合テスト | 4.2、10 | `strace` 下のテストだけ | 判断待ち |
| 署名付きリリース、ツール自身の SBOM | 2.4、4.7 | チェックサムだけ | 判断待ち |
| `O_NOATIME`、同一 inode の重複排除、大きなファイルの先頭だけを読む扱い | 6 | ない | 判断待ち |
| `secret` 型（パスワードが「設定されている」ことの記録） | 4.5、7.3 | ない。パスワードの項目は読み捨てる | 判断待ち |

機能:

| 項目 | 設計の場所 | いまの状態 |
|---|---|---|
| Windows でのスキャン・変換・レポート、レジストリ、Schannel、証明書ストア | 1.2、4、5、6、8 | 未実装（ビルドはできるが、書き込みを拒否する。配布していない） |
| `merge`、集約 JSON、数百〜数千ホストの集約表示 | 3.2、7.4、9.1 H | 未実装（`report` は 200 ファイルまで） |
| `scan` の `--exclude-from`・`--collectors`・`--format`・`--workers`・`--rules-mode`・`--dry-run` | 3.2 | 未実装 |
| `--process-info`（稼働プロセス） | 3.2、5.3、9.1 D | 未実装（最も優先度の低い将来のタスク） |
| レポートの英語（`--lang`）、絞り込み・検索・並べ替え | 7.4、9.2 L | 未実装（日本語固定、JavaScript なし） |
| CBOM の版の指定、CSV の CP932、`convert` での再評価 | 7.2 | 未実装（CBOM は 1.6 固定） |
| ルールだけでアプリを足せる構造、層の順と演算の宣言、版の大小比較 | 5.3、5.4、7.3 | アプリごとにコードがある。既定値表は版の完全一致と補間 |
| GnuTLS / NSS / libssh / Kerberos の設定、`ssh_config`、パスワードハッシュ方式 | 5.2 | 未実装 |
| NSS DB、CRL、PGP 鍵、PuTTY PPK、keytab | 5.5 | 未実装 |
| IIS、OpenVPN、strongSwan / Libreswan、vsftpd、OpenLDAP | 5.3 | 未実装（順番は 12 章） |
| 証明書同士の関連付け（発行者の参照） | 4.4、7.2 | 未実装 |
| Shift_JIS / EUC-JP の設定ファイルのデコード | 1.2、2.4 | 未実装 |
| `host.id`（ホストの同一性）、時点間の差分 | 7.2、7.4 | 未実装 |
| JSON Schema の同梱、ストリーミングでの書き出し | 7.2 | 未実装 |
| 実効値の差分テストを CI で行うこと、VM・Windows での結合テスト、性能・負荷テスト | 5.4、10 | CI にはない（差分テストは検証ラボで手動） |

---

## 10. テスト方針

- テスト駆動（期待される入出力からテストを先に書き、失敗を確認してから実装）。
- パーサ・解決ロジック: 実物の設定ファイル（ディストリ・版別の既定設定）をフィクスチャとしたゴールデンテスト。
- `safefs`・`platform` はインターフェース越しに偽のマウント表／レジストリを注入して単体テスト。
- 安全性の回帰テスト: 禁止 import 検査、バイナリのシンボル検査、`strace` 下の結合テスト（ネットワーク名前空間なしでのテストは【未実装】）、出力ファイル権限、秘密値がどの出力にも現れないこと（既知の秘密値を仕込んだフィクスチャで全出力を検索）。
- ファジング: 証明書、鍵、キーストア、ELF、パッケージ DB、`ld.so.cache`、設定文法（nginx、Apache、sshd、`openssl.cnf`）。そのほかのパーサ（JAR、Spring の設定、`server.xml` など）のファジングは【未実装】。
- 実 OS での結合テスト: CI では、Linux の各ディストリのコンテナで安全策の確認（`ci/verify-linux.sh`）を行う。VM と Windows Server での結合テストは【未実装】。
- 性能・負荷テスト: 大量ファイルのツリーでの CPU・I/O・メモリ・所要時間の計測と上限の検証。【未実装】（CI にはない）

---

## 11. 「使われている」と「入っているだけ」の区別（2026-11-12 決定）

暗号資産が実際に使われているのか、システムに入っていて使える状態にあるだけなのかは、移行の優先度付けに直結する。
結果のデータモデルで、次の2つの軸を分けて記録する（スキーマ v0 のうちに反映する。実装は Phase 1b のアプリプロファイルとあわせて行う）。

### 軸1: 値の根拠（何を見て分かったか）

設定に明記、既定値から解決、バイナリが対応しているだけ、ソースコードに記述、ファイルとして存在、など。現在の `state` がこれにあたる。

### 軸2: 利用の確からしさ

| 段階 | 意味 | 根拠の例 |
|---|---|---|
| 稼働中 | プロセスが動いていて、そのライブラリを実際に読み込んでいる | `/proc/<pid>/exe`、`maps`（`--process-info` 指定時のみ） |
| 有効 | 起動するよう設定されたサービスが使う | systemd の有効化状態、Windows サービスの開始種別 |
| 参照あり | 有効かどうかは不明だが、設定ファイルから指されている | サーバーの設定が指す証明書・鍵のパス |
| 導入のみ | 入っているだけで、使う設定が見当たらない | パッケージは導入済みだがサービスは無効、どこからも参照されない鍵 |
| 不明 | 判断材料がない | 探索で見つけた出所不明のファイル |

出現ごとに、段階とその根拠（どのファイルのどの記述から判断したか）を記録する。
「導入のみ」も捨てない。どこからも参照されていない秘密鍵は、放置された鍵として報告する価値がある。

### 決定事項

- **サービスの有効化状態は既定で読む。** systemd は `/etc/systemd/system/` 配下のリンクの有無、Windows はレジストリのサービス定義から読める。コマンド実行もプロセス情報の読み取りも要らない。
- **ログは根拠に使わない。** 量が多く、個人情報を含み得るため。
- **表現**: 暗号スイートなど設定から分かるものは「許可されている」と表現し、「使われている」とは書かない。

### このツールでは分からないこと（結果とレポートに明示する）

- 実際にネゴシエーションされている暗号（設定から言えるのは「提示・許可されている」まで）
- 「有効」と「稼働中」の差（起動設定があっても止まっていることがあり、手動起動やソケット起動で動いていることもある）
- クライアント側の利用（定期実行されるスクリプトなどからの利用は、サービスとしては見えない）
- ソースコードに書かれた処理が、本番で動いているかどうか

### レポートでの見せ方（2026-11-12 決定）

レポートを開いたときは、「有効」以上（起動するよう設定されたサービスが使っているもの）を前面に出す。
「導入のみ」は件数つきの見出しにまとめ、クリックで開く。畳んだ部分の件数は必ず表示する。
どこからも参照されていない秘密鍵のように注意が必要なものは、畳まずに別枠で目立たせる。
CSV と CBOM には常に全件を出す。

---

## 12. タスク計画（2026-11-14 時点）

対応するアプリは、調査資料の A ランクを、実利用の多さで並べ直した順に進める（利用者と確認）。各アプリは「実物で測る → 参照モデルで再現する → テストを書く → 実装する →
コンテナの中で kagiya を動かして実測と突き合わせる → 設計・限界を追記する」の順に進め、区切りごとにリファクタリングを挟む（コードと、この設計書・限界の文書）。

| 順 | 内容 | 状態 |
|---|---|---|
| 済 | 基盤、証明書・鍵・キーストア、OS とライブラリ、sshd、nginx、Apache httpd、HAProxy、stunnel、Postfix、PostgreSQL、Dovecot、MariaDB / MySQL、レポート、CBOM | 済（records.md） |
| 済 | Java の 1 段目（JDK の既定）、2 段目（パッケージの Tomcat。JDK の実装と OpenSSL の実装） | 済 |
| 1 | Spring Boot（組み込みの Tomcat、JAR の中の設定）。2.7 以降の全パッチ版（117 版）を測った。起動の定義は systemd のユニットと supervisord のプログラムから読み（そのまま実行できる JAR の `<名前>.conf` を含む）、読めない JAR は「すべての JDK で同じ結果のときだけ確定」 | 実装済み（差分テストで不一致 0）。残り: 管理用の待ち受けの値（いまは「不明」で記録）、クラスパスの `config/`（あれば「不明」） |
| 1 | JAR に同梱された暗号ライブラリの棚卸し、Bouncy Castle 形式のキーストアの識別 | 実装済み。各ライブラリの PQC 対応の版（出典つき）は未着手 |
| 2 | WildFly | 未着手 |
| 3 | ASP.NET Core（Kestrel） | 未着手 |
| 4 | A ランクの残り: OpenSSH クライアント → rsyslog・Zabbix → OpenVPN・strongSwan・Libreswan → OpenLDAP・Samba・Kerberos・FreeIPA → 鍵ファイルの項目 | 未着手 |
| 5 | Node.js の版ごとの TLS の既定 | 未着手 |
| 最後 | プロセス情報の読み取り（明示的に指定したときだけ。実行ファイルとライブラリのパスを、判断の材料にする） | 未着手。優先度は最も低い（2026-11-14、利用者が決定） |

測定の進め方: 定期実行などの自動化はせず、必要なときに手で測る。表にない版は、パッケージ名・上流の版・ディストリの系列が同じでリリースだけ違う場合に限り補い、確度を下げる
（Java の JDK だけは、開発元の版が同じなら配布元をまたいで補う）。測定の効率化は、パッケージのキャッシュ（`lab/cache/`）まで。

当初のフェーズ計画（Phase 0〜6）は、付録 A.3 に移した。

---

## 13. 追加開発の候補

実装の途中で出た要望・気づきのうち、12 章の計画に入れていないもの、または時期を決めて後に回したもの。

| 項目 | 内容 | 検討時期 |
|---|---|---|
| CA 証明書の署名方式別グルーピング | 信頼ストアの CA 証明書（1台あたり数百件）を、署名方式（例: SHA-256 with RSA、ECDSA with SHA-384）ごとにまとめて表示する。件数の多い「導入のみ」の一覧を把握しやすくする | Phase 3（実際の画面レイアウトを見て決める） |
| SUSE 系の rpm データベース（NDB 形式） | 現在は Berkeley DB と SQLite のみ対応 | 要望があれば |
| 外部ルールの署名検証 | ルールを書ける人は実行権限で読める情報の一部を出力に導けるため、署名で改ざんを防ぐ | Phase 6 |
| パス・Subject の仮名化オプション | 出力を社外に渡す場合の配慮 | Phase 6 |
| 国内で利用の多い商用ミドルウェアのプロファイル | WebLogic、WebSphere、HULFT など | 要望に応じて |
| ログを根拠にした「実際に使われた暗号」の把握 | 量と個人情報の懸念から v1 では行わない（11 章） | v1 以降 |
| ASP.NET Core（Kestrel） | 自分で TLS を待ち受け、設定がデータ（`appsettings.json`）にある。Linux では OpenSSL を使うので既存の表を使える見込み（実物で確かめる） | WildFly の後（2026-11-14、利用者が決定） |
| Node.js の版ごとの TLS の既定 | JDK の 1 段目と同じ位置づけ（アプリが何も指定しない場合の既定）。TLS の設定はコードに書かれることが多いので、読めるのは既定まで | A ランクの残りの後（2026-11-14、利用者が決定） |

対象外にしたもの（2026-11-14、利用者が決定）: アプリ層の暗号の設定（Laravel / Rails / CakePHP の設定ファイルにある暗号化やハッシュの方式など）。
これらの設定ファイルは PHP や Ruby のコードで、ソースコードを見ないという原則に反する。開発環境の CI/CD に組み込む別種のツールに任せる。
Spring Framework、Struts、Next.js は TLS を自分で受けないので単独では扱わず、前段の Web サーバーやアプリケーションサーバーの対応と、ライブラリの棚卸しで拾う。
Java アプリの起動のしかたは、systemd と supervisord の定義から読む（Spring Boot のそのまま実行できる JAR は、標準の起動スクリプトが取り込む `<名前>.conf` の「名前=値」だけを読む。シェルとしては実行しない）。init.d のスクリプト（SysVinit）、自作の起動スクリプト、ジョブ管理ツールの定義は解釈せず、
実行中のプロセスも見ない。起動の定義が読めない JAR は、導入されているすべての JDK で結果が同じ場合だけ確定とし、違えば JDK ごとの結果を候補として並べる。

---

## 付録 A. 当初の設計のうち、採らなかったもの

要件（[requirements.md](./requirements.md)）と当初の設計にあったが、その後の検討で対象外にしたもの。経緯が分かるよう、当初の文面を残している。

| 項目 | 決定 | 理由 |
|---|---|---|
| A.1 ソースコード解析 | 2026-11-14、利用者が対象外と決定 | このツールを動かす場面（サーバー上での確認）ではソースコードが存在しないと考えられる。開発環境の CI/CD に組み込む別種のツールに任せる |
| A.2 バイナリ・クラスファイルから API の参照を拾うこと | 2026-11-14、利用者が実装しないと決定 | 検証ラボでの試算で、設定や環境変数から名前を取る書き方は拾えず、同梱ライブラリの中の名前（17,703 クラスに 795 件）はアプリの利用と関係がないことが分かった。自社のコードが別の JAR に分かれていると、入れ子の JAR を開かない限り拾えない |
| A.3 当初のフェーズ計画 | 2026-11-14、いまのタスク計画（12 章）に置き換え | 実利用の多いアプリから順に進める形に変えた |
| A.4 プロセス情報の読み取り | 既定では読まない。明示的に指定したときだけ読む機能は、将来のタスク（優先度は最も低い。2026-11-14、利用者が決定） | 当初の案を、将来の実装の出発点として残す |

### A.1 ソースコード解析（当初の 5.6）

対象言語（初期）: Java、VB.NET、C#、PowerShell、シェルスクリプト（sh/bash 系。Windows バッチは Phase 6）。
VB.NET と C# は同じ .NET の API を使うため、**API ルールは `source/dotnet/` に1本化して共有**し、言語ごとに持つのは字句解析器だけとする（PowerShell からの .NET 型利用も同じルールを参照する）。言語は「字句解析器（コード）＋ルール（データ）」の組で追加できる。

正規化（スタイル差の吸収）— 言語ごとの軽量な字句解析器でトークン列に変換してから照合する:
- コメント除去、空白・改行・行継続（VB の `_`、シェルの `\`、PowerShell のバッククォート）の正規化
- 大文字小文字を区別しない言語（VB.NET、PowerShell）の識別子の畳み込み
- 文字列リテラルの連結の畳み込み（`"AES" + "/CBC/" + "PKCS5Padding"`）、Java の Unicode エスケープの復元
- 完全修飾名と import/Imports による短縮名の同一視、PowerShell の別名・パラメータ省略形の正規化
- 同一ファイル内の定数（`static final String ALG = "AES"` 等）の単純な置換。これ以上のデータフロー解析はしない
- 文字コード: BOM、UTF-8 妥当性、UTF-16、Shift_JIS、EUC-JP を判定し、**字句解析の前に**デコード（Shift_JIS の 2 バイト目が `\` と重なる問題を避ける）
- 多数のルールを全ファイルに適用するコストを抑えるため、リテラル文字列による前段フィルタで候補ルールを絞る

照合ルールはトークン列上のパターン（呼び出し・型参照・コマンド＋オプション）で、引数からアルゴリズム指定文字列を捕捉し、
カタログの解釈器（例: JCA の `"AES/CBC/PKCS5Padding"`、`"AES"` 単独指定時のプロバイダ既定モード）で正規化する。

対応 API（初期）:
- Java: JCA/JCE（`Cipher`, `MessageDigest`, `Signature`, `KeyPairGenerator`, `KeyGenerator`, `Mac`, `SecretKeyFactory`, `KeyAgreement`, `SSLContext` 等）、Bouncy Castle（軽量 API・PQC 含む）、Google Tink、Apache Commons Codec、Spring Security Crypto、Jasypt、JWT ライブラリ（jjwt、Nimbus JOSE）、Guava Hashing
- .NET（VB.NET・C# 共通）: `System.Security.Cryptography`（各 `*.Create`、`*CryptoServiceProvider`、`*Managed`、`CryptoConfig`）、Bouncy Castle C#、DPAPI、CNG/CAPI の P/Invoke 宣言、`ServicePointManager.SecurityProtocol`
- PowerShell: .NET 型の利用、`New-SelfSignedCertificate`、`Get-FileHash`、`ConvertTo-SecureString`、`Protect-CmsMessage`、TLS 設定系
- シェル: `openssl` 各サブコマンド、`ssh-keygen`、`gpg`、`keytool`、`curl`/`wget` の TLS オプション、`md5sum`/`sha*sum`、`certutil` 等

設定ファイル: `application.properties`/`.yml`（Spring の `server.ssl.*` 等）、`java.security`、`web.config`/`app.config`（`machineKey`、WCF のアルゴリズムスイート）、`appsettings.json`、ビルド定義（`pom.xml`、`build.gradle`、`*.vbproj`、`packages.config`）中の暗号ライブラリ依存。

### A.2 バイナリ解析（当初の 5.7）

逆アセンブル・逆コンパイルは行わず、ファイル形式上のメタデータと文字列のみを読む。

| 形式 | 読むもの |
|---|---|
| ELF | 動的セクション（`DT_NEEDED`、soname）、動的シンボル（未定義シンボル＝利用 API、例: `EVP_aes_256_gcm`）、静的リンクされたライブラリの版文字列、Go バイナリのビルド情報（依存モジュール） |
| PE | インポート表・遅延インポート表（`bcrypt.dll`, `ncrypt.dll`, `crypt32.dll`, `advapi32.dll` の暗号 API、OpenSSL 系 DLL）、バージョンリソース、版文字列 |
| .NET アセンブリ | マネージド PE のインポート表には暗号 API が現れないため、CLI メタデータ（型参照・メンバー参照の名前、ユーザー文字列）を読む。Java の定数プールと同じ位置づけで、逆コンパイルではない |
| Java class / JAR / WAR / EAR | 定数プール中のアルゴリズム名文字列と暗号 API へのメソッド参照。入れ子アーカイブは深さ・サイズ・展開率に上限 |

バイナリ由来の検出は「使用の可能性」（`state: capability`）として、設定やソース由来の検出と区別する。

段階の分け方（2026-11-14）: 段階 1「どのライブラリの、どの版があるか」は扱う（5.6）。段階 2「どの API を参照しているか」（上の表の、動的シンボル、インポート表、CLI メタデータ、定数プール）は
実装しない。段階 3「実際にどう呼ばれるか」は当初から対象外。段階 2 の試算の方法と結果は、records.md の 6 章にある。

### A.3 当初のフェーズ計画

各フェーズの終わりに動く成果物を出す。データモデル（JSON スキーマ）は Phase 3 完了まで `v0`（互換性を保証しない）とし、コレクタの実装で得た知見を反映してから `v1` として固定する。

| フェーズ | 内容 | 完了条件 |
|---|---|---|
| **0 基盤と縦切り** | リポジトリ／CI、禁止 import・`syscall` 使用箇所・シンボルの検査、CLI 骨格、`safefs`（Linux/Windows。ハンドル相対走査、ネットワーク FS 回避、除外、権限エラー記録）、Windows API ラッパ（レジストリ、ACL、ドライブ種別、優先度、Job）、優先度低下と流量制限、コアダンプ無効化、seccomp、出力権限、ログ、ルールローダ／`rules export`・`validate`、**PEM 証明書ファイル → 結果 JSON の最小の縦切り** | RHEL 8・Ubuntu 16.04・Windows Server 2016 の実機／実イメージで起動。通信なしの結合テスト（strace、ロード済みモジュール検査）が通る。負荷試験で流量制限の既定値を確定 |
| **1a 証明書・鍵** | 暗号カタログ初版、ASN.1（BER/DER）リーダ、X.509・CSR・各形式の鍵、JKS・PKCS#12（外側構造）、Linux の証明書ストア、JSON・CSV 出力 | 公開テストベクタと実ファイル群でのゴールデンテスト、ファジング |
| **1b Linux の事実収集** | OS 暗号設定、rpm DB・dpkg からのパッケージ版特定、**リンクしている暗号ライブラリの特定**（ELF の `DT_NEEDED` の解決、ライブラリ内の版文字列。実効値解決の前提となる最小限の ELF 読取）、アプリプロファイル機構、OpenSSH / nginx / Apache httpd の設定値（`configured` のみ） | 対象ディストリ各版の既定設定を正しく読める。各アプリが使う暗号ライブラリとそのパッケージ版を特定できる |
| **1c 実効値解決** | 解決モデルとフック、OpenSSL 暗号文字列展開、正解データ基盤。まず sshd で実証し、次に nginx / Apache | CI の正解データ（`sshd -T` 等）との一致 |
| **2 Windows** | Schannel・.NET 等の OS 設定、証明書ストア（レジストリ／ファイル）、IIS、HTTP.sys（形式調査を冒頭に実施）、OS ビルド別既定値 | Windows Server 2016/2019/2022 の実機で検証 |
| **3 レポート・集約・変換** | HTML レポート（単一／複数／多数ホスト）、`merge`（集約 JSON）、CBOM 変換（公式スキーマ検証）、評価ポリシー、`v1` スキーマ固定 | 数千ホスト分の合成データで、集約とレポート生成がメモリ・時間の上限内に収まる |
| **4 ソースコード解析** | 字句解析器（Java、VB.NET、C#、PowerShell、シェル）、主要 API ルール、設定ファイル、文字コード対応 | スタイル違いの同値コード群で同一結果 |
| **5 バイナリ解析** | ELF（Phase 1b の読取を拡張: 動的シンボル、静的リンクの版文字列）/ PE / .NET メタデータ / class・JAR、探索起点配下のバイナリ全般への適用 | ファジング、実バイナリ群でのテスト |
| **6 拡充・堅牢化** | アプリプロファイル拡充（Postfix、Dovecot、Tomcat、HAProxy、DB、VPN、国内で利用の多い商用ミドルウェアは要望に応じて）、時系列差分ビュー、PGP/PPK・NSS DB 等、性能試験、利用者向け文書の整備 | v1.0 |

フェーズ横断で最初の配布から行うこと: 署名付きバイナリとチェックサムの公開、ツール自身の SBOM、利用者向け文書（読み取り対象一覧、負荷と副作用の説明、通信しないことの確認手順）。

主なリスクと置き方:
- 実効値解決の正しさ（最大のリスク）→ 1c で正解データとの突き合わせを完了条件にする。
- Windows の API ラッパ自作と安全策 → Phase 0 に含め、早期に実機で検証。
- 形式パーサの自作量（BER、PKCS#12、キーストア、ELF/PE）→ 対応形式を段階的に増やし、ファジングを各フェーズの完了条件に含める。
- Go の最小対応 OS とサポート期間 → 版を固定し続けるとセキュリティ修正が止まるため、対応 OS の切り捨て方針を文書化する。

### A.4 プロセス情報の読み取り（当初の 4.5 の案）

当初の設計にあった記述（実装していない）:

- **ソースコードの証跡**: 生の行は出力しない。一致した API 名と、抽出したアルゴリズム指定文字列、ファイル・行・列のみ。
- **プロセス情報**: 既定では一切読まない。`--process-info` が明示された場合に限り、Linux で `/proc/<pid>/exe`（実行ファイルのパス）と `/proc/<pid>/maps`（ロード済みライブラリのパス）だけを読む。
  `/proc/<pid>/environ`・`cmdline`・`mem` など秘密を含み得るものは、オプションの有無にかかわらず**読まない**（`cmdline` も引数にパスワードが含まれることがあるため対象外とする）。Windows ではプロセスを調べない。

いまの扱い（2026-11-14、利用者が決定）: 既定では、稼働中のプロセスは読まない。Java アプリを動かす JDK は、起動の定義から読み、読めなければ、
導入されているすべての JDK で結果が同じ場合だけ確定とする。明示的な指定があった場合にプロセスの情報も読んで判断の材料にする機能は、
将来的に実装する（優先度は最も低く、12 章の計画の最後）。
