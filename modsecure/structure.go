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
	Id                          string                                `json:"id"`
	AuditHeader                 *SectionAAuditHeader                  `json:"auditHeader"`
	RequestHeader               *SectionBRequestHeader                `json:"requestHeader"`
	RequestBody                 []string                              `json:"requestBody"`
	IntendedResponseHeader      *SectionDIntendedResponseHeader       `json:"intendedResponseHeader"`
	IntendedResponseBody        *SectionEIntendedResponseBody         `json:"intendedResponseBody"`
	ResponseHeader              *SectionFResponseHeaders              `json:"responseHeader"`
	ResponseBody                []string                              `json:"ResponseBody"`
	AuditLogTrailer             *SectionHAuditLogTrailer              `json:"auditLogTrailer"`
	ReducedMultipartRequestBody *SectionIReducedMultipartRequestBody  `json:"reducedMultipartRequestBody"`
	MultipartFilesInformation   *SectionJMultipartFileInformation     `json:"multipartFilesInformation"`
	MatchedRulesInformation     *SectionKMatchedRuleInformation       `json:"matchedRulesInformation"`
	AuditLogFooter              *SectionZAuditLogFooter               `json:"auditLogFooter"`
	RecordLine                  int                                   `json:"recordLine"`
}

type SectionAAuditHeader struct {
	timestamp       time.Time `json:"timestamp"`
	transactionID   string    `json:"transactionId"`
	sourceIP        net.IP    `json:"sourceIp"`
	sourcePort      uint16    `json:"sourcePort"`
	destinationIP   net.IP    `json:"destinationIp"`
	destinationPort uint16    `json:"destinationPort"`
}

type SectionBRequestHeader struct {
	Protocol string             `json:"protocol"`
	Method   string             `json:"method"`
	Path     string             `json:"path"`
	Header   *map[string]string `json:"header"`
}

type SectionCRequestBody struct {
}

type SectionDIntendedResponseHeader struct {
}

type SectionEIntendedResponseBody struct {
}

type SectionFResponseHeaders struct {
	Protocol string             `json:"protocol"`
	Status   uint16             `json:"status"`
	Header   *map[string]string `json:"header"`
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
