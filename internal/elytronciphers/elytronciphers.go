// Package elytronciphers は、WildFly（Elytron）の暗号の指定を、Elytron と同じ規則で解釈する。
//
// Elytron は、指定（server-ssl-context の cipher-suite-filter。OpenSSL に似た書き方）を、OpenSSL には渡さず、自分の持つ表で解釈する。
// 解釈の規則は、上流のソース（wildfly-elytron の org.wildfly.security.ssl.CipherSuiteSelector、CipherSuitePredicate、MechanismDatabase。
// 1.16.1.Final と 2.9.4.Final で同一）をそのまま写した。OpenSSL の規則とは違うところがある:
//
//   - 結果は、JDK が対応しているスイートの並びから選ばれる（並びは JDK の順。表の順ではない）
//   - 「!」「-」「+」の後ろの知らない語は、エラーにならず、無視される。先頭に書いた知らない語は、エラーになる
//   - 「A+B」の中の知らない語は、無視される（ただし、先頭の語が知らない語なら、エラー）
//   - 「@STRENGTH」のほかの「@...」は、エラー
//
// 表は、ルール（rules/java/wildfly.yaml）が持つ。ここでは、通信もコマンドの実行もしない。
package elytronciphers

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"kagiya/internal/ruleset"
)

// maxExpression は、解釈する式の長さの上限。
const maxExpression = 4096

type entry struct {
	suite   *ruleset.ElytronSuite
	aliases map[string]bool
}

// database は、Elytron の MechanismDatabase にあたる。名前（標準の名前と別名）と、OpenSSL 式の名前から、スイートを引く。
type database struct {
	byName    map[string]*entry
	byOpenSSL map[string]*entry
}

func newDatabase(suites []ruleset.ElytronSuite, explicit []ruleset.ElytronAlias) *database {
	db := &database{byName: map[string]*entry{}, byOpenSSL: map[string]*entry{}}
	aliases := map[string]string{}
	alias := func(name, target string) {
		aliases[name] = target
	}
	for _, a := range explicit {
		alias(a.Name, a.Target)
		if strings.HasPrefix(a.Name, "TLS_") {
			alias("SSL_"+a.Name[4:], a.Target)
		}
	}
	for i := range suites {
		s := &suites[i]
		e := &entry{suite: s, aliases: map[string]bool{}}
		if _, dup := db.byName[s.Name]; !dup {
			db.byName[s.Name] = e
		}
		for _, n := range s.OpenSSL {
			if _, dup := db.byOpenSSL[n]; !dup {
				db.byOpenSSL[n] = e
			}
			if s.Kx == "DHE" {
				// 「DHE」と「EDH」を入れ替えた名前でも引ける（引けるだけで、その名前のスイートとしては選ばれない。Elytron の挙動のとおり）
				if swapped := swapEDH(n); db.byOpenSSL[swapped] == nil {
					db.byOpenSSL[swapped] = e
				}
			}
		}
		if strings.HasPrefix(s.Name, "TLS_") {
			alias("SSL_"+s.Name[4:], s.Name)
		}
	}
	for name, target := range aliases {
		for hops := 0; hops < 8; hops++ {
			next, ok := aliases[target]
			if !ok {
				break
			}
			target = next
		}
		if _, dup := db.byName[name]; dup {
			continue
		}
		if e, ok := db.byName[target]; ok && e.suite.Name == target {
			e.aliases[name] = true
		}
	}
	// 別名は、すべての別名の行き先が決まってから登録する（別名を、別の別名の行き先にしない）
	for _, e := range uniqueEntries(db.byName) {
		for a := range e.aliases {
			db.byName[a] = e
		}
	}
	return db
}

func uniqueEntries(m map[string]*entry) []*entry {
	var out []*entry
	for name, e := range m {
		if e.suite.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func swapEDH(name string) string {
	parts := strings.Split(name, "-")
	for i, p := range parts {
		switch p {
		case "EDH":
			parts[i] = "DHE"
		case "DHE":
			parts[i] = "EDH"
		}
	}
	return strings.Join(parts, "-")
}

type predicate func(*entry) bool

func kx(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Kx, values) }
}

func auth(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Auth, values) }
}

func enc(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Enc, values) }
}

func mac(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Mac, values) }
}

func protocol(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Protocol, values) }
}

func level(values ...string) predicate {
	return func(e *entry) bool { return in(e.suite.Level, values) }
}

func in(v string, values []string) bool {
	for _, x := range values {
		if v == x {
			return true
		}
	}
	return false
}

func all(ps ...predicate) predicate {
	return func(e *entry) bool {
		for _, p := range ps {
			if !p(e) {
				return false
			}
		}
		return true
	}
}

func anyOf(ps ...predicate) predicate {
	return func(e *entry) bool {
		for _, p := range ps {
			if p(e) {
				return true
			}
		}
		return false
	}
}

func not(p predicate) predicate {
	return func(e *entry) bool { return !p(e) }
}

func named(name string) predicate {
	return func(e *entry) bool {
		return in(name, e.suite.OpenSSL) || e.aliases[name] || e.suite.Name == name
	}
}

var (
	matchAll             = not(enc("NULL"))
	matchComplementOfAll = enc("NULL")
	matchAnonDH          = all(kx("DHd", "DHr", "DHE"), auth("NULL"))
	matchDefaultDeletes  = anyOf(auth("NULL"), enc("NULL"), func(e *entry) bool { return e.suite.Export }, level("LOW"), protocol("SSLv2"))
)

// words は、式に書ける語（Elytron の getSimplePredicateByName のとおり）。ここにない語は、スイートの名前として引く。
var words = map[string]predicate{
	"HIGH":        level("HIGH"),
	"MEDIUM":      level("MEDIUM"),
	"LOW":         level("LOW"),
	"EXP":         level("EXP40", "EXP56"),
	"EXPORT":      level("EXP40", "EXP56"),
	"EXPORT40":    level("EXP40"),
	"EXPORT56":    level("EXP56"),
	"NULL":        enc("NULL"),
	"eNULL":       enc("NULL"),
	"aNULL":       auth("NULL"),
	"kRSA":        kx("RSA"),
	"aRSA":        auth("RSA"),
	"RSA":         anyOf(kx("RSA"), auth("RSA")),
	"kDHr":        kx("DHr"),
	"kDHd":        kx("DHd"),
	"kDH":         kx("DHr", "DHd"),
	"kDHE":        kx("DHE"),
	"kEDH":        kx("DHE"),
	"DHE":         all(kx("DHE"), not(auth("NULL"))),
	"EDH":         all(kx("DHE"), not(auth("NULL"))),
	"ADH":         matchAnonDH,
	"DH":          all(kx("DHE", "DHd", "DHr", "ECDHe", "ECDHr", "ECDHE"), auth("DH", "ECDH", "NULL")),
	"kECDHr":      kx("ECDHr"),
	"kECDHe":      kx("ECDHe"),
	"kECDH":       kx("ECDHe", "ECDHr"),
	"kEECDH":      kx("ECDHE"),
	"kECDHE":      kx("ECDHE"),
	"ECDHE":       all(kx("ECDHE"), not(auth("NULL"))),
	"EECDHE":      all(kx("ECDHE"), not(auth("NULL"))),
	"AECDH":       all(kx("ECDHe", "ECDHr", "ECDHE"), auth("NULL")),
	"ECDH":        kx("ECDHe", "ECDHr", "ECDHE"),
	"DSS":         auth("DSS"),
	"aDSS":        auth("DSS"),
	"aDH":         auth("DH"),
	"aECDH":       auth("ECDH"),
	"ECDSA":       auth("ECDSA"),
	"aECDSA":      auth("ECDSA"),
	"kFZA":        kx("FZA"),
	"aFZA":        auth("FZA"),
	"eFZA":        enc("FZA"),
	"FZA":         anyOf(kx("FZA"), auth("FZA"), enc("FZA")),
	"TLSv1.2":     protocol("TLSv1.2"),
	"TLSv1":       protocol("TLSv1"),
	"SSLv3":       protocol("SSLv3"),
	"SSLv2":       protocol("SSLv2"),
	"AES128":      enc("AES128", "AES128GCM"),
	"AES256":      enc("AES256", "AES256GCM"),
	"AES":         enc("AES128", "AES128GCM", "AES256", "AES256GCM"),
	"AESGCM":      enc("AES128GCM", "AES256GCM"),
	"ARIA":        enc("ARIA128", "ARIA128GCM", "ARIA256", "ARIA256GCM"),
	"ARIA128":     enc("ARIA128", "ARIA128GCM"),
	"ARIA256":     enc("ARIA256", "ARIA256GCM"),
	"ARIAGCM":     enc("ARIA128GCM", "ARIA256GCM"),
	"CAMELLIA128": enc("CAMELLIA128"),
	"CAMELLIA256": enc("CAMELLIA256"),
	"CAMELLIA":    enc("CAMELLIA128", "CAMELLIA256"),
	"3DES":        enc("3DES"),
	"DES":         enc("DES"),
	"RC4":         enc("RC4"),
	"RC2":         enc("RC2"),
	"IDEA":        enc("IDEA"),
	"SEED":        enc("SEED"),
	"MD5":         mac("MD5"),
	"SHA":         mac("SHA1"),
	"SHA1":        mac("SHA1"),
	"SHA256":      mac("SHA256"),
	"SHA384":      mac("SHA384"),
	"aGOST":       auth("GOST01", "GOST94"),
	"aGOST01":     auth("GOST01"),
	"aGOST94":     auth("GOST94"),
	"kGOST":       kx("GOST"),
	"GOST94":      mac("GOST94"),
	"GOST89MAC":   mac("GOST89MAC"),
	"kPSK":        kx("PSK"),
	"aPSK":        auth("PSK"),
	"PSK":         anyOf(auth("PSK"), kx("PSK")),
	"kRSAPSK":     kx("RSAPSK"),
	"RSAPSK":      kx("RSAPSK"),
	"DHEPSK":      kx("DHEPSK"),
	"EDHPSK":      kx("DHEPSK"),
	"kDHEPSK":     kx("DHEPSK"),
	"kEDHPSK":     kx("DHEPSK"),
	"EECDHPSK":    kx("ECDHEPSK"),
	"kEECDHPSK":   kx("ECDHEPSK"),
	"ECDHEPSK":    kx("ECDHEPSK"),
	"kECDEHPSK":   kx("ECDHEPSK"), // 上流のソースの綴りのまま
}

type opKind int

const (
	opAdd opKind = iota
	opRemove
	opDelete
	opPushToEnd
	opSort
)

type op struct {
	kind opKind
	pred predicate
}

type parser struct {
	db   *database
	text string
	pos  int
	ops  []op
}

// word は、区切りの文字（または末尾）の手前までを読む。区切りの文字は読まない。
func (p *parser) word(delimiters string) string {
	start := p.pos
	for p.pos < len(p.text) && strings.IndexByte(delimiters, p.text[p.pos]) < 0 {
		p.pos++
	}
	return p.text[start:p.pos]
}

// nextIs は、次の 1 文字を読み、それが c かどうかを返す（c でなくても読み進める。Elytron の挙動のとおり）。
func (p *parser) nextIs(c byte) bool {
	if p.pos >= len(p.text) {
		return false
	}
	p.pos++
	return p.text[p.pos-1] == c
}

const wordDelimiters = "+:, "

func (p *parser) simple(word string) predicate {
	if pred, ok := words[word]; ok {
		return pred
	}
	if p.db.byOpenSSL[word] == nil && p.db.byName[word] == nil {
		return nil
	}
	return named(word)
}

// predicate は、語 1 つ、または「+」でつないだ語を読む。知らない語は nil（「+」が続く場合はエラー）。
func (p *parser) predicate(word string) (predicate, error) {
	item := p.simple(word)
	if !p.nextIs('+') {
		return item, nil
	}
	if item == nil {
		return nil, fmt.Errorf("unknown word %q before '+'", word)
	}
	list := []predicate{item}
	for {
		if next := p.simple(p.word(wordDelimiters)); next != nil {
			list = append(list, next)
		}
		if !p.nextIs('+') {
			break
		}
	}
	return all(list...), nil
}

func (p *parser) add(kind opKind, pred predicate) {
	if pred != nil {
		p.ops = append(p.ops, op{kind, pred})
	}
}

func (p *parser) parse() error {
	for p.pos < len(p.text) {
		c := p.text[p.pos]
		p.pos++
		switch {
		case c == '+' || c == '-' || c == '!':
			pred, err := p.predicate(p.word(wordDelimiters))
			if err != nil {
				return err
			}
			p.add(map[byte]opKind{'+': opPushToEnd, '-': opRemove, '!': opDelete}[c], pred)
		case c == '@':
			if word := p.word("=:"); word != "STRENGTH" {
				return fmt.Errorf("unknown special word %q", word)
			}
			if p.nextIs('=') {
				return errors.New("'=' is not allowed")
			}
			p.ops = append(p.ops, op{kind: opSort})
		case c == '=':
			return errors.New("'=' is not allowed")
		case c == ',' || c == ':' || isJavaWhitespace(c):
		case isLetterOrDigit(c):
			p.pos--
			name := p.word(wordDelimiters)
			pred, err := p.predicate(name)
			if err != nil {
				return err
			}
			if pred != nil {
				p.add(opAdd, pred)
				break
			}
			switch name {
			case "DEFAULT":
				p.add(opAdd, matchAll)
				p.add(opDelete, matchDefaultDeletes)
			case "COMPLEMENTOFDEFAULT":
				p.add(opAdd, matchAnonDH)
			case "ALL":
				p.add(opAdd, matchAll)
			case "COMPLEMENTOFALL":
				p.add(opAdd, matchComplementOfAll)
			default:
				return fmt.Errorf("unknown word %q", name)
			}
		default:
			return fmt.Errorf("unexpected character at %d", p.pos-1)
		}
	}
	return nil
}

func isLetterOrDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// isJavaWhitespace は、Java の Character.isWhitespace にあたる（ASCII の範囲）。
func isJavaWhitespace(c byte) bool {
	return c == ' ' || c >= 0x09 && c <= 0x0d || c >= 0x1c && c <= 0x1f
}

type item struct {
	entry *entry
	name  string
}

// orderedSet は、入れた順を保つ名前の集合。
type orderedSet struct {
	names []string
	has   map[string]bool
}

func (s *orderedSet) add(name string) {
	if !s.has[name] {
		s.has[name] = true
		s.names = append(s.names, name)
	}
}

func (s *orderedSet) remove(name string) {
	if !s.has[name] {
		return
	}
	delete(s.has, name)
	for i, n := range s.names {
		if n == name {
			s.names = append(s.names[:i:i], s.names[i+1:]...)
			return
		}
	}
}

// run は、supported（JDK が対応しているスイートの名前。JDK の順）に、ops を順に適用する。
// lookup は、supported の名前を引く表。main は、選ばれた名前を引き直す表（TLS 1.2 以前の表。Elytron の挙動のとおり）。
func run(ops []op, lookup, main *database, supported []string) []string {
	var items []item
	position := map[*entry]int{}
	for _, name := range supported {
		e := lookup.byName[name]
		if e == nil {
			continue
		}
		if i, ok := position[e]; ok {
			items[i].name = name // 同じスイートの別の名前。位置は先のもの、名前は後のもの
			continue
		}
		position[e] = len(items)
		items = append(items, item{e, name})
	}
	enabled := &orderedSet{has: map[string]bool{}}
	for _, o := range ops {
		switch o.kind {
		case opAdd:
			for _, it := range items {
				if o.pred(it.entry) {
					enabled.add(it.name)
				}
			}
		case opRemove:
			for _, it := range items {
				if o.pred(it.entry) {
					enabled.remove(it.name)
				}
			}
		case opDelete:
			kept := items[:0:0]
			for _, it := range items {
				if o.pred(it.entry) {
					enabled.remove(it.name)
				} else {
					kept = append(kept, it)
				}
			}
			items = kept
		case opPushToEnd:
			var stay, pushed []string
			for _, name := range enabled.names {
				if e := main.byName[name]; e != nil && o.pred(e) {
					pushed = append(pushed, name)
				} else {
					stay = append(stay, name)
				}
			}
			enabled.names = append(stay, pushed...)
		case opSort:
			sort.SliceStable(enabled.names, func(i, j int) bool {
				return bits(main, enabled.names[i]) > bits(main, enabled.names[j])
			})
		}
	}
	return append([]string{}, enabled.names...)
}

func bits(db *database, name string) int {
	if e := db.byName[name]; e != nil {
		return e.suite.Bits
	}
	return 0
}

func checkText(text string) error {
	if len(text) > maxExpression {
		return errors.New("the expression is too long")
	}
	for i := 0; i < len(text); i++ {
		// Elytron は ASCII 以外の文字（空白や英数字の扱いが Java の規則による）も読むが、ここでは解釈しない
		if text[i] >= 0x80 || text[i] == 0 {
			return errors.New("the expression has a character that is not interpreted here")
		}
	}
	return nil
}

// Evaluate は、cipher-suite-filter の式を解釈し、supported（JDK が対応しているスイートの名前。JDK の順）のうち、選ばれるものを、選ばれる順に返す。
// Elytron が受け付けない式は、エラーにする。TLS 1.3 のスイートは、この式では選ばれない（EvaluateNames を使う）。
func Evaluate(tb *ruleset.WildFlyTable, expr string, supported []string) ([]string, error) {
	if tb == nil {
		return nil, errors.New("no table")
	}
	if err := checkText(expr); err != nil {
		return nil, err
	}
	db := newDatabase(tb.Suites, tb.Aliases)
	p := &parser{db: db, text: expr}
	if err := p.parse(); err != nil {
		return nil, err
	}
	return run(p.ops, db, db, supported), nil
}

// EvaluateNames は、cipher-suite-names（TLS 1.3 用。スイートの名前を「:」で区切って並べる）を解釈する。
// 表にない名前があれば、エラーにする（Elytron も受け付けない）。結果は、書かれた順。
func EvaluateNames(tb *ruleset.WildFlyTable, names string, supported []string) ([]string, error) {
	if tb == nil {
		return nil, errors.New("no table")
	}
	if err := checkText(names); err != nil {
		return nil, err
	}
	db := newDatabase(tb.TLS13, nil)
	var ops []op
	for _, name := range strings.Split(names, ":") {
		if name == "" {
			continue
		}
		if db.byOpenSSL[name] == nil {
			return nil, fmt.Errorf("unknown TLS 1.3 cipher suite name %q", name)
		}
		ops = append(ops, op{opAdd, named(name)})
	}
	return run(ops, db, newDatabase(tb.Suites, tb.Aliases), supported), nil
}
