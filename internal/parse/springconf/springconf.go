// Package springconf は、Spring Boot の設定ファイル（application.properties / application.yml）から、TLS に関わる項目を取り出す。
//
// 取り出すのは、あらかじめ許可した項目だけ（暗号スイート、プロトコル、キーストアや証明書の場所と種類など）。
// それ以外の項目は、名前も値も持たない。パスワードの項目は許可していない。
// 鍵や証明書の中身を設定に直接書ける項目（private-key など）は、値が場所（パス）の形のときだけ持ち、
// 中身が書かれていた場合は「直接書かれていた」ことだけを記録する。
//
// 読み方（実測で確かめたもの）: 同じ場所では properties が yml に勝つ。有効にしたプロファイル（spring.profiles.active）の
// 設定ファイルが上書きする。有効にしていないプロファイルの設定は読まない。
// 環境変数、起動時の引数、JAR の外の設定ファイルによる上書きは、ここでは分からない（呼び出す側が注記する）。
package springconf

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	maxKeys     = 1024 // 持つ項目の数の上限
	maxValue    = 4096 // 値の長さの上限
	maxDepth    = 32   // YAML の入れ子の上限
	maxNodes    = 200000
	maxDocs     = 64
	maxProfiles = 16
)

// Value は、項目の値と、書かれていた場所。
type Value struct {
	Value string
	File  string
	Line  int
}

// Config は、読み取った設定。項目の名前は、正規の形（小文字、「-」区切り）で引く。
type Config struct {
	Profiles []string // 設定ファイルの中で有効にされていたプロファイル
	// 値に ${...} を含み、解釈しなかった項目
	Unresolved map[string]bool
	// 鍵や証明書の中身が、設定に直接書かれていた項目（値は持たない）
	Inline map[string]bool
	// 読めなかったものの説明
	Problems []string

	values map[string]Value  // 正規化した名前 → 値
	names  map[string]string // 正規化した名前 → 表示用の名前（最初に見た書き方を「-」区切りにしたもの）
}

// 許可する項目（正規化した名前に対する正規表現）。ここにない項目は持たない。
var allowed = regexp.MustCompile(`^(` +
	`server\.(port|ssl\.(enabled|protocol|enabledprotocols(\[\d+\])?|ciphers(\[\d+\])?|keystore|keystoretype|keystoreprovider|keyalias|` +
	`certificate|certificateprivatekey|truststore|truststoretype|trustcertificate|clientauth|bundle|servernamebundles\[\d+\]\.(servername|bundle)))` +
	`|spring\.profiles\.active(\[\d+\])?` +
	`|spring\.config\.activate\.onprofile` +
	`|spring\.ssl\.bundle\.(jks|pem)\.[a-z0-9]+\.(protocol|keystore\.(location|type|provider|certificate|privatekey)|truststore\.(location|type|provider|certificate)|` +
	`key\.alias|options\.(ciphers|enabledprotocols)(\[\d+\])?)` +
	`)$`)

// 値が「場所」の形のときだけ持つ項目（中身を直接書けるもの）。
var locationOnly = regexp.MustCompile(`(certificate|certificateprivatekey|trustcertificate|privatekey)$`)

var (
	indexSuffix = regexp.MustCompile(`\[(\d{1,4})\]$`)
	placeholder = regexp.MustCompile(`\$\{`)
	profileName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// canon は、項目の名前を正規の形にする（Spring は keyStore、key_store、KEY-STORE を同じ項目として扱う）。
func canon(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r == '-' || r == '_':
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// display は、項目の名前を、表示用の形（小文字、単語の境目を「-」）にする。
func display(key string) string {
	var b strings.Builder
	for i, r := range key {
		switch {
		case r == '_':
			b.WriteByte('-')
		case r >= 'A' && r <= 'Z':
			if i > 0 && key[i-1] >= 'a' && key[i-1] <= 'z' {
				b.WriteByte('-')
			}
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (c *Config) problem(s string) {
	if len(c.Problems) < 16 {
		c.Problems = append(c.Problems, s)
	}
}

// put は、項目を 1 つ、許可と検証を通ったものだけ持つ。
func (c *Config) put(key, value, file string, line int) {
	k := canon(key)
	if len(k) > 256 || !allowed.MatchString(k) {
		return
	}
	value = strings.TrimSpace(value)
	name := display(key)
	if strings.Contains(value, "-----BEGIN") || (locationOnly.MatchString(indexSuffix.ReplaceAllString(k, "")) && strings.ContainsAny(value, "\n\r")) {
		delete(c.values, k)
		c.Inline[name] = true
		return
	}
	if len(value) > maxValue || strings.ContainsAny(value, "\x00\n\r") {
		return
	}
	if placeholder.MatchString(value) {
		delete(c.values, k)
		c.Unresolved[name] = true
		return
	}
	if _, exists := c.values[k]; !exists && len(c.values) >= maxKeys {
		c.problem("too many settings; the rest are not kept")
		return
	}
	delete(c.Unresolved, name)
	delete(c.Inline, name)
	c.values[k] = Value{Value: value, File: file, Line: line}
	c.names[k] = name
}

// Get は、項目の値を返す。
func (c *Config) Get(key string) (Value, bool) {
	v, ok := c.values[canon(key)]
	return v, ok
}

// Keys は、持っている項目の名前（表示用の形）を、名前の順で返す。
func (c *Config) Keys() []string {
	out := make([]string, 0, len(c.values))
	for k := range c.values {
		out = append(out, c.names[k])
	}
	sort.Strings(out)
	return out
}

// List は、並びの項目（「a=x,y」または「a[0]=x」「a[1]=y」）の値と、その先頭の場所を返す。項目がなければ nil。
func (c *Config) List(key string) ([]string, Value) {
	k := canon(key)
	if v, ok := c.values[k]; ok {
		var out []string
		for _, x := range strings.Split(v.Value, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
		return out, v
	}
	type item struct {
		i int
		v Value
	}
	var items []item
	for name, v := range c.values {
		rest, ok := strings.CutPrefix(name, k+"[")
		if !ok || !strings.HasSuffix(rest, "]") {
			continue
		}
		if i, err := strconv.Atoi(strings.TrimSuffix(rest, "]")); err == nil {
			items = append(items, item{i, v})
		}
	}
	if len(items) == 0 {
		return nil, Value{}
	}
	sort.Slice(items, func(a, b int) bool { return items[a].i < items[b].i })
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, strings.TrimSpace(it.v.Value))
	}
	return out, items[0].v
}

// Load は、設定ファイルを Spring Boot の優先順で読む。get は、名前（application.properties など）から中身を返す。
func Load(get func(name string) ([]byte, bool)) *Config { return LoadWith(get, Options{}) }

// Options は、設定ファイルの外で決まること。
type Options struct {
	// 起動時の指定（--spring.profiles.active、環境変数など）で有効にされたプロファイル。ProfilesSet が真なら、設定ファイルの中の指定より優先する
	Profiles    []string
	ProfilesSet bool
}

// LoadWith は、設定ファイルを Spring Boot の優先順で読む。プロファイルは、外からの指定があればそれに、なければ設定ファイルの中の指定に従う。
func LoadWith(get func(name string) ([]byte, bool), opt Options) *Config {
	c := &Config{Unresolved: map[string]bool{}, Inline: map[string]bool{}, values: map[string]Value{}, names: map[string]string{}}
	read := func(base string, profiles map[string]bool) {
		// 同じ場所では properties が yml に勝つので、yml を先に読んで properties で上書きする
		for _, ext := range []string{".yml", ".yaml"} {
			if data, ok := get(base + ext); ok {
				c.yaml(data, base+ext, profiles)
			}
		}
		if data, ok := get(base + ".properties"); ok {
			c.properties(data, base+".properties")
		}
	}
	read("application", nil)
	// 設定ファイルの中で有効にされたプロファイル。条件つきの文書（YAML）は、有効なプロファイルが分かってから読み直す
	active := map[string]bool{}
	list, _ := c.List("spring.profiles.active")
	if opt.ProfilesSet {
		list = opt.Profiles
	}
	if len(list) > 0 {
		for _, p := range list {
			if profileName.MatchString(p) && len(c.Profiles) < maxProfiles && !active[p] {
				active[p] = true
				c.Profiles = append(c.Profiles, p)
			}
		}
	}
	if len(active) > 0 {
		read("application", active)
		for _, p := range c.Profiles {
			read("application-"+p, active)
		}
	}
	return c
}

// properties は、Java の properties の形式を読む（「名前=値」「名前:値」「名前 値」、# と ! のコメント、行末の \ での継続）。
func (c *Config) properties(data []byte, file string) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		l := strings.TrimLeft(lines[i], " \t\f")
		if l == "" || l[0] == '#' || l[0] == '!' {
			continue
		}
		// 行末の \（奇数個）は、次の行へ続く
		for strings.HasSuffix(l, "\\") && (len(l)-len(strings.TrimRight(l, "\\")))%2 == 1 && i+1 < len(lines) {
			i++
			l = l[:len(l)-1] + strings.TrimLeft(lines[i], " \t\f")
		}
		// 名前の終わり: エスケープされていない = : 空白
		end := len(l)
		for j := 0; j < len(l); j++ {
			if l[j] == '\\' {
				j++
				continue
			}
			if l[j] == '=' || l[j] == ':' || l[j] == ' ' || l[j] == '\t' {
				end = j
				break
			}
		}
		key := l[:end]
		rest := strings.TrimLeft(l[end:], " \t")
		if rest != "" && (rest[0] == '=' || rest[0] == ':') {
			rest = strings.TrimLeft(rest[1:], " \t")
		}
		c.put(key, unescape(rest), file, start)
	}
}

// unescape は、properties の値の \ を外す（\n などの制御文字は、値として持たないので、そのまま改行にする）。
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			if i+4 < len(s) {
				if n, err := strconv.ParseUint(s[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(n))
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// yaml は、YAML の設定を読む。入れ子のマップは「a.b.c」、並びは「a.b[0]」の名前にして、properties と同じ扱いにする。
// 1 つのファイルに複数の文書がある場合、プロファイルの条件（spring.config.activate.on-profile）つきの文書は、
// そのプロファイルが有効なときだけ読む（profiles が nil のときは、条件つきの文書を読まない）。
func (c *Config) yaml(data []byte, file string, profiles map[string]bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	nodes := 0
	for doc := 0; doc < maxDocs; doc++ {
		var root yaml.Node
		err := dec.Decode(&root)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			c.problem(file + ": the YAML cannot be read")
			return
		}
		type kv struct {
			key, value string
			line       int
		}
		var items []kv
		ok := true
		var walk func(n *yaml.Node, path string, depth int)
		walk = func(n *yaml.Node, path string, depth int) {
			nodes++
			if !ok || depth > maxDepth || nodes > maxNodes {
				if ok {
					c.problem(file + ": the YAML is nested too deeply or is too large")
				}
				ok = false
				return
			}
			switch n.Kind {
			case yaml.DocumentNode:
				for _, x := range n.Content {
					walk(x, path, depth)
				}
			case yaml.MappingNode:
				for i := 0; i+1 < len(n.Content); i += 2 {
					k := n.Content[i]
					if k.Kind != yaml.ScalarNode {
						continue
					}
					p := k.Value
					if path != "" {
						p = path + "." + k.Value
					}
					walk(n.Content[i+1], p, depth+1)
				}
			case yaml.SequenceNode:
				for i, x := range n.Content {
					walk(x, path+"["+strconv.Itoa(i)+"]", depth+1)
				}
			case yaml.ScalarNode:
				items = append(items, kv{path, n.Value, n.Line})
			case yaml.AliasNode:
				// 別名（アンカーの参照）は辿らない（小さな入力から巨大な構造を作れるため）
				c.problem(file + ": the YAML uses an alias, which is not followed")
				ok = false
			}
		}
		walk(&root, "", 0)
		if !ok {
			return
		}
		// この文書の条件（プロファイル）
		cond := ""
		for _, it := range items {
			if canon(it.key) == "spring.config.activate.onprofile" {
				cond = strings.TrimSpace(it.value)
			}
		}
		if cond != "" && !profiles[cond] {
			continue
		}
		for _, it := range items {
			c.put(it.key, it.value, file, it.line)
		}
	}
}
