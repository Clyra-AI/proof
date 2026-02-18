package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gowebpki/jcs"
)

type Domain string

const (
	DomainJSON   Domain = "json"
	DomainSQL    Domain = "sql"
	DomainURL    Domain = "url"
	DomainText   Domain = "text"
	DomainPrompt Domain = "prompt"
)

var whitespaceRE = regexp.MustCompile(`\s+`)
var trailingSemicolonRE = regexp.MustCompile(`;+[\s]*$`)
var sqlKeywordRE = regexp.MustCompile(`\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|LEFT|RIGHT|INNER|OUTER|GROUP|BY|ORDER|HAVING|LIMIT|OFFSET|AND|OR|NOT|IN|AS|ON|VALUES|SET)\b`)

func Canonicalize(input []byte, domain Domain) ([]byte, error) {
	switch domain {
	case DomainJSON:
		return jcs.Transform(input)
	case DomainSQL:
		s := normalizeWhitespace(string(input))
		s = trailingSemicolonRE.ReplaceAllString(s, "")
		s = sqlKeywordRE.ReplaceAllStringFunc(s, strings.ToLower)
		s = strings.TrimSpace(s)
		return []byte(s), nil
	case DomainText, DomainPrompt:
		return []byte(normalizeWhitespace(string(input))), nil
	case DomainURL:
		u, err := url.Parse(strings.TrimSpace(string(input)))
		if err != nil {
			return nil, err
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		nq := url.Values{}
		for _, k := range keys {
			nq[k] = q[k]
		}
		u.RawQuery = nq.Encode()
		return []byte(u.String()), nil
	default:
		return input, nil
	}
}

func DigestHex(input []byte, domain Domain) (string, error) {
	canonical, err := Canonicalize(input, domain)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeWhitespace(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = whitespaceRE.ReplaceAllString(s, " ")
	return s
}
