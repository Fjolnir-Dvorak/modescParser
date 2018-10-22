package modsecure

import (
	"net"
	"time"
)

type EStructure int

const (
	NIL         EStructure = -1
	AuditHeader EStructure = iota
	RequestHeader
	RequestBody
	IntendedResponseHeader
	IntendedResponseBody
	ResponseHeader
	ResponseBody
	AuditLogTrailer
	ReducedMultipartRequestBody
	MultipartFilesInformation
	MatchedRulesInformation
	AuditLogFooter
)

var (
	keyToEStructure = map[rune]EStructure{
		'A': AuditHeader,
		'B': RequestHeader,
		'C': RequestBody,
		'D': IntendedResponseHeader,
		'E': IntendedResponseBody,
		'F': ResponseHeader,
		'G': ResponseBody,
		'H': AuditLogTrailer,
		'I': ReducedMultipartRequestBody,
		'J': MultipartFilesInformation,
		'K': MatchedRulesInformation,
		'Z': AuditLogFooter,
	}
)

type Record struct {
	Id                          string
	AuditHeader                 *SectionAAuditHeader
	RequestHeader               *SectionBRequestHeader
	RequestBody                 []string
	IntendedResponseHeader      *SectionDIntendedResponseHeader
	IntendedResponseBody        *SectionEIntendedResponseBody
	ResponseHeader              *SectionFResponseHeaders
	ResponseBody                []string
	AuditLogTrailer             *SectionHAuditLogTrailer
	ReducedMultipartRequestBody *SectionIReducedMultipartRequestBody
	MultipartFilesInformation   *SectionJMultipartFileInformation
	MatchedRulesInformation     *SectionKMatchedRuleInformation
	AuditLogFooter              *SectionZAuditLogFooter
}

type SectionAAuditHeader struct {
	timestamp       time.Time
	transactionID   string
	sourceIP        net.IP
	sourcePort      uint16
	destinationIP   net.IP
	destinationPort uint16
}

type SectionBRequestHeader struct {
	Protocol string
	Method   string
	Path     string
	Header   *map[string]string
}

type SectionCRequestBody struct {
}

type SectionDIntendedResponseHeader struct {
}

type SectionEIntendedResponseBody struct {
}

type SectionFResponseHeaders struct {
	Protocol string
	Status   uint16
	Header   *map[string]string
}

type SectionGResponseBody struct {
}

type SectionHAuditLogTrailer struct {
}

type SectionIReducedMultipartRequestBody struct {
}

type SectionJMultipartFileInformation struct {
}

type SectionKMatchedRuleInformation struct {
}

type SectionZAuditLogFooter struct {
}
