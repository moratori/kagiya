// Package elytronciphers は、WildFly（Elytron）の暗号の指定を、Elytron の表で解釈する。
package elytronciphers

import (
	"errors"

	"kagiya/internal/ruleset"
)

// Evaluate は、cipher-suite-filter の式を解釈し、supported のうち選ばれるものを、選ばれる順に返す。
func Evaluate(tb *ruleset.WildFlyTable, expr string, supported []string) ([]string, error) {
	return nil, errors.New("not implemented")
}

// EvaluateNames は、cipher-suite-names（TLS 1.3 用）の指定を解釈する。
func EvaluateNames(tb *ruleset.WildFlyTable, names string, supported []string) ([]string, error) {
	return nil, errors.New("not implemented")
}
