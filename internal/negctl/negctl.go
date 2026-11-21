package negctl

import "golang.org/x/text/language"

func Parse(s string) ([]language.Tag, []float32, error) { return language.ParseAcceptLanguage(s) }
