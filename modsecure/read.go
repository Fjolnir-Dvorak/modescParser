package modsecure

import (
	"bufio"
	//"compress/gzip"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type readBuffer struct {
	readRecordMutex             *sync.Mutex
	readSectionMutex            *sync.Mutex
	lastReadLine    string
	hasLastReadLine bool
	reader          *bufio.Reader
	IsFinished      bool
	linePointer     int
	LastSegmentKey  EStructure
	DebugSkipper    bool
}

type RecordReader struct {
	buffer *readBuffer
	Err error
}

type RecordAndRaw struct {
	Record *Record
	Raw string
}

var (
	errEndReached = errors.New("End reached")
	errNotMyRecord = errors.New("Not my Segment")
	// parses: "--26bc3c6f-A--"
	sectionStartRegex = regexp.MustCompile(`^--([a-z0-9]{8})-([ABCDEFGHIJKZ])--$`)
	// parses: "[08/Oct/2018:00:00:01 +0200] W7qB4cCoFIQAAHtbutUAAAFI 92.38.32.36 36354 192.168.20.132 443"
	logHeaderRegex = regexp.MustCompile(`^\[([0-9]{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/[0-9]{4}(?::[0-9]{2}){3}\s\+[0-9]{4})\]\s([a-zA-Z0-9\-@]{24,27})\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s([0-9]+)\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s([0-9]+)$`)
	// parses: "POST /callback/auth/context/notify/v1.0 HTTP/2.0"
	headerReqHeadRegex = regexp.MustCompile(`^([A-Z]+)\s([^\s]+)\s([A-Z]+/[0-9.]+)$`)
	headerResHeadRegex = regexp.MustCompile(`^([A-Z]+/[0-9.]+)\s([0-9]{3,})\s*[A-Za-z\s]*$`)
	layoutDate = "02/Jan/2006:15:04:05 -0700"
)

// TODO: Files need to be closed on panic or on other stuff.

func CreateRecordReader(filename string, debugSkipper bool) (reader *RecordReader, err error) {
	buffer, err := createBuffer(filename, debugSkipper)
	if err != nil {
		return nil, err
	}
	return &RecordReader{
		buffer:buffer,
	}, nil
}

func (r *RecordReader) Next(historyBuffer *strings.Builder) (record *Record, err error) {
	return ReadSingleRecord(r.buffer, historyBuffer)
}

func (r *RecordReader) HasNext() (bool) {
	return !r.buffer.IsFinished
}

func (r *RecordReader) PeekToNextValidStart(historyBuffer *strings.Builder) (err error) {
	return JumpToNextValidStart(r.buffer, historyBuffer)
}

func (r *RecordReader) Iter() <- chan *Record {
	ch := make(chan *Record)
	go func() {
		defer close(ch)
		var historyBuffer *strings.Builder
		historyBuffer = &strings.Builder{}
		for r.HasNext() {
			item, err := r.Next(historyBuffer)
			historyBuffer.Reset()
			if err != nil {
				r.Err = err
				return
			}
			ch <- item
		}
	}()
	return ch
}

func (r *RecordReader) IterLossy() <- chan *RecordAndRaw {
	ch := make(chan *RecordAndRaw)
	go func() {
		defer close(ch)
		var historyBuffer *strings.Builder
		historyBuffer = &strings.Builder{}
		for r.HasNext() {
			recAndRaw := &RecordAndRaw{}
			item, err := r.Next(historyBuffer)
			if err != nil {
				r.PeekToNextValidStart(historyBuffer)
				recAndRaw.Raw = historyBuffer.String()
				historyBuffer.Reset()
				ch <- recAndRaw
			}
			recAndRaw.Record = item
			recAndRaw.Raw = historyBuffer.String()
			historyBuffer.Reset()
			ch <- recAndRaw
		}
	}()
	return ch
}

func createBuffer(filename string, debugSkipper bool) (buffer *readBuffer, err error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	if err != nil {
		//fmt.Println("ERROR: Could not open file")
		return nil, err
	}
	//test, _ := gzip.NewReader(file)
	reader := bufio.NewReader(file)
	buffer = &readBuffer{
		lastReadLine:    "",
		hasLastReadLine: false,
		reader:          reader,
		IsFinished:      false,
		readRecordMutex: &sync.Mutex{},
		readSectionMutex: &sync.Mutex{},
		LastSegmentKey: NIL,
		DebugSkipper: debugSkipper,
	}
	return buffer, nil
}

func (r *readBuffer) ReadLine() (line string, err error) {
	if r.IsFinished {
		return "", io.EOF
	}
	if r.hasLastReadLine {
		r.hasLastReadLine = false
		r.linePointer = r.linePointer + 1
		return r.lastReadLine, nil
	} else {
		line, err = r.getLineOrLast()
		r.linePointer = r.linePointer + 1
		return line, err
	}
}

func (r *readBuffer) getLineOrLast() (line string, err error) {
	for {
		readString, err := r.reader.ReadString('\n')
		if err != nil {
			return readString, err
		} else {
			readString = strings.Trim(readString, "\n")
			if r.DebugSkipper && strings.HasPrefix(readString, "#") {
				r.linePointer = r.linePointer + 1
				continue
			}
			return readString, nil
		}
	}
}

func (r *readBuffer) PeekLine() (line string, err error) {
	if !r.hasLastReadLine {
		line, err = r.getLineOrLast()
		r.lastReadLine = line
		r.hasLastReadLine = true
	}
	return r.lastReadLine, err
}

func (r *readBuffer) AcceptPeekedLine() {
	if r.hasLastReadLine {
		r.linePointer = r.linePointer + 1
		r.hasLastReadLine = false
	}
}
func (r *readBuffer) GetPeekedLineNumber() int {
	if r.hasLastReadLine {
		return r.linePointer + 1
	} else {
		return r.linePointer
	}
}

func JumpToNextValidStart(reader *readBuffer, historyBuffer *strings.Builder) (err error) {
	reader.readRecordMutex.Lock()
	defer reader.readRecordMutex.Unlock()
	for {
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
		success, _, sectionType := parseSectionDefinition(firstLine)
		if !success {
			historyBuffer.WriteString(firstLine)
			historyBuffer.WriteRune('\n')
			reader.AcceptPeekedLine()
			continue
		}
		if sectionType != AuditHeader {
			historyBuffer.WriteString(firstLine)
			historyBuffer.WriteRune('\n')
			reader.AcceptPeekedLine()
			continue
		}
		return nil
	}
}

func ReadSingleRecord(reader *readBuffer, historyBuffer *strings.Builder) (record *Record, err error) {
	record = &Record{}
	reader.readRecordMutex.Lock()
	defer reader.readRecordMutex.Unlock()
	for {
		err = record.ReadSection(reader, historyBuffer)
		if err != nil {
			if record.Id == "" {
				if reader.IsFinished {
					return nil, errEndReached
				}
				return nil, errors.WithMessage(err, "Failed to create new record")
			}
			if err == errEndReached || err == errNotMyRecord {
				if reader.LastSegmentKey != AuditLogFooter {
					return nil, errors.New(fmt.Sprintf("Record is not complete. Stopped parsing at line %d", reader.linePointer))
				}
				return record, nil
			}
			return nil, errors.WithMessage(err, fmt.Sprintf("Error in line: %d", reader.linePointer))
		}
	}
}

func (r *Record) ReadSection(reader *readBuffer, historyBuffer *strings.Builder) (err error) {
	reader.readSectionMutex.Lock()
	reader.readSectionMutex.Unlock()
	firstLine, err := reader.PeekLine()
	firstLineInt := reader.GetPeekedLineNumber()
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
		if sectionType != AuditHeader {
			return errors.New("Invalid section start")
		}
		r.Id = sectionName
	} else if r.Id != sectionName {
		return errNotMyRecord
	} else if sectionType <= reader.LastSegmentKey {
		return errNotMyRecord
	}
	historyBuffer.WriteString(firstLine)
	historyBuffer.WriteRune('\n')
	reader.AcceptPeekedLine()
	reader.LastSegmentKey = sectionType
	body, err := readSectionBody(reader, historyBuffer)
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
			r.RecordLine = firstLineInt
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
		return nil, errors.New(fmt.Sprintf("Invalid Response Header: \"%s\"", body[0]))
	}
	subbody := body[1:]
	for _, elem := range subbody {
		splitterated := strings.SplitN(elem, ": ", 2)
		if len(splitterated) < 2 {
			return nil, errors.New("Invalid Header")
		}
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
		if len(splitterated) < 2 {
			return nil, errors.New("Invalid Header")
		}
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
		return nil, errors.New(fmt.Sprintf("Invalid Header, Header string: \"%s\"", body[0]))
	}
	date, err := time.Parse(layoutDate, parsedHeader[1])
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
	if destIp == nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, DestIp is broken: %s", parsedHeader[5]))
	}
	destPort, err := strconv.Atoi(parsedHeader[6])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Header, DestPort is broken: %s", parsedHeader[6]))
	}
	return &SectionAAuditHeader{
		Timestamp:       date,
		TransactionID:   id,
		SourceIP:        sourceIp,
		SourcePort:      uint16(sourcePort),
		DestinationIP:   destIp,
		DestinationPort: uint16(destPort),
	}, nil
}

func readSectionBody(reader *readBuffer, historyBuffer *strings.Builder) (body []string, err error) {
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
			historyBuffer.WriteRune('\n')
			reader.AcceptPeekedLine()
			break
		}
		if isSectionDefinition(line) {
			// End of section. A new section begins. Leaving the head in the buffer for further parsing.
			break
		}
		historyBuffer.WriteString(line)
		historyBuffer.WriteRune('\n')
		reader.AcceptPeekedLine()
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
