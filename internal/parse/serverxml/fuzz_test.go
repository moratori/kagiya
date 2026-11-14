package serverxml

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add([]byte(`<Server><Service><Connector port="8443" SSLEnabled="true"><SSLHostConfig protocols="TLSv1.3"><Certificate certificateKeystoreFile="conf/k.p12"/></SSLHostConfig></Connector></Service></Server>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "b">]><Server>&a;</Server>`))
	f.Fuzz(func(t *testing.T, data []byte) { Parse(data) })
}
