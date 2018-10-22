package modsecure

import (
	"bufio"
	"fmt"
	"github.com/araddon/dateparse"
	"github.com/pkg/errors"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	errEndReached = errors.New("End reached")
)

type readBuffer struct {
	// TODO lock this struct with mutex
	lastReadLine    string
	hasLastReadLine bool
	reader          *bufio.Reader
	IsFinished      bool
}

func createBuffer(filename string) (buffer *readBuffer, err error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	if err != nil {
		//fmt.Println("ERROR: Could not open file")
		return nil, err
	}
	reader := bufio.NewReader(file)
	buffer = &readBuffer{
		lastReadLine:    "",
		hasLastReadLine: false,
		reader:          reader,
		IsFinished:      false,
	}
	return buffer, nil
}

func (r readBuffer) ReadLine() (line string, err error) {
	// TODO: lock
	if r.hasLastReadLine {
		r.hasLastReadLine = false
		return r.lastReadLine, nil
	} else {
		return r.getLineOrLast()
	}
}

func (r readBuffer) getLineOrLast() (line string, err error) {
	// TODO: lock
	readString, err := r.reader.ReadString('\n')
	if err != nil {
		return readString, err
	} else {
		readString = strings.Trim(readString, "\n")
		return readString, nil
	}
}

func (r readBuffer) PeekLine() (line string, err error) {
	if !r.hasLastReadLine {
		// TODO: lock
		line, err = r.getLineOrLast()
		r.lastReadLine = line
		r.hasLastReadLine = true
	}
	return r.lastReadLine, err
}

func (r readBuffer) AcceptPeekedLine() {
	r.hasLastReadLine = false
}

var (
	// parses: "--26bc3c6f-A--"
	sectionStartRegex = regexp.MustCompile(`^--([a-z0-9]{8})-([ABCDEFGHIJKZ])--$`)
	// parses: "[08/Oct/2018:00:00:01 +0200] W7qB4cCoFIQAAHtbutUAAAFI 92.38.32.36 36354 192.168.20.132 443"
	logHeaderRegex = regexp.MustCompile(`^\[([0-9]{2}/(?:Jan|Feb|Mar|Apr|Mai|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/[0-9]{4}(?::[0-9]{2}){3}\s\+[0-9]{4})\]\s([a-zA-Z0-9]{24})\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s([0-9]+)\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s([0-9]+)$`)
	// parses: "POST /callback/auth/context/notify/v1.0 HTTP/2.0"
	headerReqHeadRegex = regexp.MustCompile(`^([A-Z]+)\s([^\s]+)\s([A-Z]+/[0-9.]+)$`)
	headerResHeadRegex = regexp.MustCompile(`^([A-Z]+/[0-9.]+)\s([0-9]{3,})$`)
)

func ReadRecord(reader *readBuffer) (record *Record, err error){
	record = &Record{}
	for {
		err = record.ReadSection(reader)
		if err != nil {
			if record.Id == "" {
				if reader.IsFinished {
					return nil, errEndReached
				}
				return nil, errors.WithMessage(err, "Failed to create new record")
			}
			if err == errEndReached {
				return record, nil
			}
			return nil, err
		}
	}
}

func (r Record) ReadSection(reader *readBuffer) (err error) {
	firstLine, err := reader.PeekLine()
	if err != nil {
		if err == io.EOF {
			//fmt.Println("Finished")
			reader.IsFinished = true
			return errEndReached
		}
		//fmt.Println("ERROR: unexpected behaviour while reading file line by line")
		return err
	}
	success, sectionName, sectionType := parseSectionDefinition(firstLine)
	//success, _, _ := parseSectionDefinition(firstLine)
	if !success {
		return errors.New("Invalid section start")
	}
	if r.Id == "" {
		r.Id = sectionName
	} else if r.Id != sectionName {
		return errors.New("Not my Id")
	}
	reader.AcceptPeekedLine()
	body, err := readSectionBody(reader)
	switch sectionType {
	case AuditHeader:
		{
			if r.AuditHeader != nil {
				return errors.New("AuditHeader already set.")
			}
			val, err := parseAuditHeader(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse AuditHeader")
			}
			r.AuditHeader = val
		}
	case RequestHeader:
		{
			if r.RequestHeader != nil {
				return errors.New("RequestHeader already set.")
			}
			val, err := parseRequestHeader(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse RequestHeader")
			}
			r.RequestHeader = val
		}
	case RequestBody:
		{
			if r.RequestBody != nil {
				return errors.New("RequestBody already set.")
			}
			val, err := parseRequestBody(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse RequestBody")
			}
			r.RequestBody = val
		}
	case IntendedResponseHeader:
		{
			if r.IntendedResponseHeader != nil {
				return errors.New("IntendedResponseHeader already set.")
			}
			val, err := parseIntendedResponseHeader(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse IntendedResponseHeader")
			}
			r.IntendedResponseHeader = val
		}
	case IntendedResponseBody:
		{
			if r.IntendedResponseBody != nil {
				return errors.New("IntendedResponseBody already set.")
			}
			val, err := parseIntendedResponseBody(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse IntendedResponseBody")
			}
			r.IntendedResponseBody = val
		}
	case ResponseHeader:
		{
			if r.ResponseHeader != nil {
				return errors.New("ResponseHeader already set.")
			}
			val, err := parseResponseHeader(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse ResponseHeader")
			}
			r.ResponseHeader = val
		}
	case ResponseBody:
		{
			if r.ResponseBody != nil {
				return errors.New("ResponseBody already set.")
			}
			val, err := parseResponseBody(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse ResponseBody")
			}
			r.ResponseBody = val
		}
	case AuditLogTrailer:
		{
			if r.AuditLogTrailer != nil {
				return errors.New("AuditLogTrailer already set.")
			}
			val, err := parseAuditLogTrailer(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse AuditLogTrailer")
			}
			r.AuditLogTrailer = val
		}
	case ReducedMultipartRequestBody:
		{
			if r.ReducedMultipartRequestBody != nil {
				return errors.New("ReducedMultipartRequestBody already set.")
			}
			val, err := parseReducedMultipartRequestBody(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse ReducedMultipartRequestBody")
			}
			r.ReducedMultipartRequestBody = val
		}
	case MultipartFilesInformation:
		{
			if r.MultipartFilesInformation != nil {
				return errors.New("MultipartFilesInformation already set.")
			}
			val, err := parseMultipartFilesInformation(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse MultipartFilesInformation")
			}
			r.MultipartFilesInformation = val
		}
	case MatchedRulesInformation:
		{
			if r.MatchedRulesInformation != nil {
				return errors.New("MatchedRulesInformation already set.")
			}
			val, err := parseMatchedRulesInformation(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse MatchedRulesInformation")
			}
			r.MatchedRulesInformation = val
		}
	case AuditLogFooter:
		{
			if r.AuditLogFooter != nil {
				return errors.New("AuditLogFooter already set.")
			}
			val, err := parseAuditLogFooter(body)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse AuditLogFooter")
			}
			r.AuditLogFooter = val
		}
	}
	if err != io.EOF {
		//fmt.Println("Finished")
		return err
	}
	return nil
}
func parseAuditLogFooter(body []string) (section *SectionZAuditLogFooter, err error) {
	// TODO: implement this section
	return nil, nil
}
func parseMatchedRulesInformation(body []string) (section *SectionKMatchedRuleInformation, err error) {
	// TODO: implement this section
	return nil, nil
}
func parseMultipartFilesInformation(body []string) (section *SectionJMultipartFileInformation, err error) {
	// TODO: implement this section
	return nil, nil
}
func parseReducedMultipartRequestBody(body []string) (section *SectionIReducedMultipartRequestBody, err error) {
	// TODO: implement this section
	return nil, nil
}
func parseAuditLogTrailer(body []string) (section *SectionHAuditLogTrailer, err error) {
	// TODO: implement this section
	return nil, nil
}
func parseResponseBody(body []string) (section []string, err error) {
	return body, nil
}
func parseResponseHeader(body []string) (section *SectionFResponseHeaders, err error) {
	if len(body) < 1 {
		return nil, errors.New("Body is empty")
	}
	header := make(map[string]string)
	// First line: POST /callback/auth/context/pageview/v1.0 HTTP/1.1
	// All following lines are one line headers.
	parsedLine := headerResHeadRegex.FindStringSubmatch(body[0])
	if parsedLine == nil {
		return nil, errors.New("Invalid Body")
	}
	subbody := body[1:]
	for _, elem := range subbody {
		splitterated := strings.SplitN(elem, ": ", 2)
		header[splitterated[0]] = splitterated[1]
	}
	statusCode, err := strconv.Atoi(parsedLine[2])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, StatusCode is broken: %s", parsedLine[2]))
	}
	section = &SectionFResponseHeaders{
		Protocol: parsedLine[1],
		Status:   uint16(statusCode),
		Header:   &header,
	}
	return section, nil
}
func parseIntendedResponseBody(body []string) (section *SectionEIntendedResponseBody, err error) {
	// Not implemented in https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats
	return nil, nil
}

func parseIntendedResponseHeader(body []string) (section *SectionDIntendedResponseHeader, err error) {
	// Not implemented in https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats
	return nil, nil
}

func parseRequestBody(body []string) (requestBody []string, err error) {
	return body, nil
}

func parseRequestHeader(body []string) (section *SectionBRequestHeader, err error) {
	if len(body) < 1 {
		return nil, errors.New("Body is empty")
	}
	header := make(map[string]string)
	// First line: POST /callback/auth/context/pageview/v1.0 HTTP/1.1
	// All following lines are one line headers.
	parsedLine := headerReqHeadRegex.FindStringSubmatch(body[0])
	if parsedLine == nil {
		return nil, errors.New("Invalid Body")
	}
	subbody := body[1:]
	for _, elem := range subbody {
		splitterated := strings.SplitN(elem, ": ", 2)
		header[splitterated[0]] = splitterated[1]
	}
	section = &SectionBRequestHeader{
		Protocol: parsedLine[3],
		Method:   parsedLine[1],
		Path:     parsedLine[2],
		Header:   &header,
	}
	return section, nil
}

func parseAuditHeader(body []string) (section *SectionAAuditHeader, err error) {
	if len(body) != 1 {
		return nil, errors.New("Header is longer than 1")
	}
	parsedHeader := logHeaderRegex.FindStringSubmatch(body[0])
	if parsedHeader == nil {
		return nil, errors.New("Invalid Header")
	}
	date, err := dateparse.ParseStrict(parsedHeader[1])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, Date is broken: %s", parsedHeader[1]))
	}
	id := parsedHeader[2]
	sourceIp := net.ParseIP(parsedHeader[3])
	if sourceIp == nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, SourceIp is broken: %s", parsedHeader[3]))
	}
	sourcePort, err := strconv.Atoi(parsedHeader[4])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, SourcePort is broken: %s", parsedHeader[4]))
	}
	destIp := net.ParseIP(parsedHeader[5])
	if sourceIp == nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, DestIp is broken: %s", parsedHeader[5]))
	}
	destPort, err := strconv.Atoi(parsedHeader[6])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, DestPort is broken: %s", parsedHeader[6]))
	}
	return &SectionAAuditHeader{
		timestamp:       date,
		transactionID:   id,
		sourceIP:        sourceIp,
		sourcePort:      uint16(sourcePort),
		destinationIP:   destIp,
		destinationPort: uint16(destPort),
	}, nil
}

func readSectionBody(reader *readBuffer) (body []string, err error) {
	lines := make([]string, 0, 1)
	for {
		line, err := reader.PeekLine()
		if err != nil {
			if err != io.EOF {
				//fmt.Println("Finished")
				return nil, err
			}
		}
		if strings.TrimSpace(line) == "" {
			// End of section. Removing empty line from read buffer.
			reader.AcceptPeekedLine()
			break
		}
		if isSectionDefinition(line) {
			// End of section. A new section begins. Leaving the head in the buffer for further parsing.
			break
		}

		lines = append(lines, line)
	}
	return lines, err
}

func isSectionDefinition(line string) (success bool) {
	success, _, _ = parseSectionDefinition(line)
	return success
}

func parseSectionDefinition(line string) (success bool, sectionName string, sectionType EStructure) {
	match := sectionStartRegex.FindStringSubmatch(line)
	if match == nil {
		return false, "", NIL
	} else {
		sectionType := keyToEStructure[[]rune(match[2])[0]]
		return true, match[1], sectionType // match 0 is the full match
	}
}
