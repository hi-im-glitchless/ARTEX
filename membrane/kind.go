// Package membrane rewrites outbound LLM traffic into an alias universe and
// maps replies back to real values.
package membrane

// Kind classifies a sensitive value detected in outbound text.
type Kind string

const (
	KindDomain     Kind = "domain"
	KindIPv4       Kind = "ipv4"
	KindIPv6       Kind = "ipv6"
	KindEmail      Kind = "email"
	KindOrg        Kind = "org"
	KindProduct    Kind = "product"
	KindPerson     Kind = "person"
	KindUsername   Kind = "username"
	KindPassword   Kind = "password"
	KindToken      Kind = "token"
	KindPhone      Kind = "phone"
	KindIBAN       Kind = "iban"
	KindNIF        Kind = "nif"
	KindCard       Kind = "card"
	KindPrivateKey Kind = "private_key"
)
