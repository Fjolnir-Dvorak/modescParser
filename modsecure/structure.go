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

//+k8s:openapi-gen=true
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

//+k8s:openapi-gen=true
type SectionAAuditHeader struct {
	Timestamp       time.Time `json:"timestamp"`
	TransactionID   string    `json:"transactionId"`
	SourceIP        net.IP    `json:"sourceIp"`
	SourcePort      uint16    `json:"sourcePort"`
	DestinationIP   net.IP    `json:"destinationIp"`
	DestinationPort uint16    `json:"destinationPort"`
}

//+k8s:openapi-gen=true
type SectionBRequestHeader struct {
	Protocol string             `json:"protocol"`
	Method   string             `json:"method"`
	Path     string             `json:"path"`
	Header   *map[string]string `json:"header"`
}

//+k8s:openapi-gen=true
type SectionCRequestBody struct {
}

//+k8s:openapi-gen=true
type SectionDIntendedResponseHeader struct {
}

//+k8s:openapi-gen=true
type SectionEIntendedResponseBody struct {
}

//+k8s:openapi-gen=true
type SectionFResponseHeaders struct {
	Protocol string             `json:"protocol"`
	Status   uint16             `json:"status"`
	Header   *map[string]string `json:"header"`
}

//+k8s:openapi-gen=true
type SectionGResponseBody struct {
}

//+k8s:openapi-gen=true
type SectionHAuditLogTrailer struct {
}

//+k8s:openapi-gen=true
type SectionIReducedMultipartRequestBody struct {
}

//+k8s:openapi-gen=true
type SectionJMultipartFileInformation struct {
}

//+k8s:openapi-gen=true
type SectionKMatchedRuleInformation struct {
}

//+k8s:openapi-gen=true
type SectionZAuditLogFooter struct {
}
