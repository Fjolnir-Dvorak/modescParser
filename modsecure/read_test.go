package modsecure

import (
	"bufio"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
	"github.com/google/go-cmp/cmp"
)

type futureBuffer struct {
	filename string
	debugSkipper bool
}

func (fb futureBuffer) create() (buffer *readBuffer) {
	buffer, err := createBuffer(fb.filename, fb.debugSkipper)
	if err != nil {
		panic(err)
	}
	return buffer
}

func Test_parseSectionDefinition(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name            string
		args            args
		wantSuccess     bool
		wantSectionName string
		wantSectionType EStructure
	}{
		{
			name: "Valid input",
			args: args{
				line: "--55da4834-A--",
			},
			wantSuccess:     true,
			wantSectionName: "55da4834",
			wantSectionType: keyToEStructure['A'],
		},
		{
			name: "Valid input modified section type",
			args: args{
				line: "--55da4834-B--",
			},
			wantSuccess:     true,
			wantSectionName: "55da4834",
			wantSectionType: keyToEStructure['B'],
		},
		{
			name: "Valid input modified section name",
			args: args{
				line: "--55da4844-A--",
			},
			wantSuccess:     true,
			wantSectionName: "55da4844",
			wantSectionType: keyToEStructure['A'],
		},
		{
			name: "Invalid section input",
			args: args{
				line: "--55$a4834-A--",
			},
			wantSuccess:     false,
			wantSectionName: "",
			wantSectionType: NIL,
		},
		{
			name: "Invalid type input",
			args: args{
				line: "--55da4834-Y--",
			},
			wantSuccess:     false,
			wantSectionName: "",
			wantSectionType: NIL,
		},
		{
			name: "Invalid empty Input",
			args: args{
				line: "",
			},
			wantSuccess:     false,
			wantSectionName: "",
			wantSectionType: NIL,
		},
		{
			name: "Invalid trailing space",
			args: args{
				line: "--55da4834-A-- ",
			},
			wantSuccess:     false,
			wantSectionName: "",
			wantSectionType: NIL,
		},
		{
			name: "Invalid leading space",
			args: args{
				line: " --55da4834-A--",
			},
			wantSuccess:     false,
			wantSectionName: "",
			wantSectionType: NIL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSuccess, gotSectionName, gotSectionType := parseSectionDefinition(tt.args.line)
			if gotSuccess != tt.wantSuccess {
				t.Errorf("parseSectionDefinition() gotSuccess = %v, want %v", gotSuccess, tt.wantSuccess)
			}
			if gotSectionName != tt.wantSectionName {
				t.Errorf("parseSectionDefinition() gotSectionName = %v, want %v", gotSectionName, tt.wantSectionName)
			}
			if gotSectionType != tt.wantSectionType {
				t.Errorf("parseSectionDefinition() gotSectionType = %v, want %v", gotSectionType, tt.wantSectionType)
			}
		})
	}
}

func Test_readSectionBody(t *testing.T) {
	type args struct {
		reader futureBuffer
	}
	testdir := "testdata/single_section/"

	tests := []struct {
		name     string
		args     args
		wantBody []string
		wantErr  bool
	}{
		{
			name: "section empty body",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_empty_body.txt",
				},
			},
			wantBody: make([]string, 0, 0),
			wantErr:  false,
		},
		{
			name: "section invalid body empty line",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_invalid_body_empty_line.txt",
				},
			},
			wantBody: []string{
				"Teststring1",
			},
			wantErr: false,
		},
		{
			name: "section multiline body",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_multiline_body.txt",
				},
			},
			wantBody: []string{
				"Teststring1",
				"Teststring2",
				"Teststring3",
			},
			wantErr: false,
		},
		{
			name: "section oneline body",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_oneline_body.txt",
				},
			},
			wantBody: []string{
				"Teststring1",
			},
			wantErr: false,
		},
		{
			name: "section oneline body EOF",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_oneline_body_EOF.txt",
				},
			},
			wantBody: []string{
				"Teststring1",
			},
			wantErr: false,
		},
		{
			name: "section with following section head",
			args: args{
				reader: futureBuffer{
					filename: testdir + "section_with_following_section_head.txt",
				},
			},
			wantBody: []string{
				"Teststring1",
			},
			wantErr: false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readBuffer := tt.args.reader.create()
			readBuffer.ReadLine() // Schmeiße die Headerzeile weg
			gotBody, err := readSectionBody(readBuffer)
			if (err != nil) != tt.wantErr {
				t.Errorf("readSectionBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(gotBody, tt.wantBody) {
				t.Errorf("readSectionBody() = %v, want %v", gotBody, tt.wantBody)
			}
		})
	}
}

//var _ = Describe("ModsecParser", func() {
//	var (
//		test bool
//	)
//
//	BeforeEach(func() {
//		test = true
//	})
//
//	Describe("Beispiel 1", func() {
//		Context("Ausführung 1", func() {
//			It("funktioniert", func() {
//				Expect(true).To(Equal(true))
//			})
//		})
//	})
//})

func Test_createBuffer(t *testing.T) {
	tests := []struct {
		name        string
		filename        string
		wantBuffer  *readBuffer
		wantErr     func(err error) bool
		wantErrName string
		debugSkipper bool
	}{
		{
			name: "Invalid file",
			filename: "HahahaIchBinNichtDa",
			wantBuffer:  nil,
			wantErr:     os.IsNotExist,
			wantErrName: "notExist",
			debugSkipper: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBuffer, err := createBuffer(tt.filename, tt.debugSkipper)
			if (err != nil) && !tt.wantErr(err) {
				t.Errorf("createBuffer() error = %v, wantErr %v", err, tt.wantErrName)
				return
			}
			if !reflect.DeepEqual(gotBuffer, tt.wantBuffer) {
				t.Errorf("createBuffer() = %v, want %v", gotBuffer, tt.wantBuffer)
			}
		})
	}
}

func Test_readBuffer_ReadLine(t *testing.T) {
	type fields struct {
		lastReadLine    string
		hasLastReadLine bool
		reader          *bufio.Reader
		IsFinished      bool
	}
	tests := []struct {
		name     string
		fields   fields
		wantLine string
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := readBuffer{
				lastReadLine:    tt.fields.lastReadLine,
				hasLastReadLine: tt.fields.hasLastReadLine,
				reader:          tt.fields.reader,
				IsFinished:      tt.fields.IsFinished,
			}
			gotLine, err := r.ReadLine()
			if (err != nil) != tt.wantErr {
				t.Errorf("readBuffer.ReadLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotLine != tt.wantLine {
				t.Errorf("readBuffer.ReadLine() = %v, want %v", gotLine, tt.wantLine)
			}
		})
	}
}

func Test_readBuffer_getLineOrLast(t *testing.T) {
	type fields struct {
		lastReadLine    string
		hasLastReadLine bool
		reader          *bufio.Reader
		IsFinished      bool
	}
	tests := []struct {
		name     string
		fields   fields
		wantLine string
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := readBuffer{
				lastReadLine:    tt.fields.lastReadLine,
				hasLastReadLine: tt.fields.hasLastReadLine,
				reader:          tt.fields.reader,
				IsFinished:      tt.fields.IsFinished,
			}
			gotLine, err := r.getLineOrLast()
			if (err != nil) != tt.wantErr {
				t.Errorf("readBuffer.getLineOrLast() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotLine != tt.wantLine {
				t.Errorf("readBuffer.getLineOrLast() = %v, want %v", gotLine, tt.wantLine)
			}
		})
	}
}

func Test_readBuffer_PeekLine(t *testing.T) {
	type fields struct {
		lastReadLine    string
		hasLastReadLine bool
		reader          *bufio.Reader
		IsFinished      bool
	}
	tests := []struct {
		name     string
		fields   fields
		wantLine string
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := readBuffer{
				lastReadLine:    tt.fields.lastReadLine,
				hasLastReadLine: tt.fields.hasLastReadLine,
				reader:          tt.fields.reader,
				IsFinished:      tt.fields.IsFinished,
			}
			gotLine, err := r.PeekLine()
			if (err != nil) != tt.wantErr {
				t.Errorf("readBuffer.PeekLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotLine != tt.wantLine {
				t.Errorf("readBuffer.PeekLine() = %v, want %v", gotLine, tt.wantLine)
			}
		})
	}
}

func Test_readBuffer_AcceptPeekedLine(t *testing.T) {
	type fields struct {
		lastReadLine    string
		hasLastReadLine bool
		reader          *bufio.Reader
		IsFinished      bool
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := readBuffer{
				lastReadLine:    tt.fields.lastReadLine,
				hasLastReadLine: tt.fields.hasLastReadLine,
				reader:          tt.fields.reader,
				IsFinished:      tt.fields.IsFinished,
			}
			r.AcceptPeekedLine()
		})
	}
}

func TestReadRecord(t *testing.T) {
	type args struct {
		reader *futureBuffer
	}
	tests := []struct {
		name       string
		args       args
		wantRecord *Record
		wantErr    bool
		jumpOver   int
	}{
		{
			name: "Read record with single section",
			args: args{
				&futureBuffer{
							filename:"testdata/single_section/section_oneline_body.txt",
							debugSkipper:false,
						},
			},
			wantRecord: &Record{
				Id:          "26bc3c6f",
				RequestBody: []string{"Teststring1"},
			},
			wantErr: false,
		},
		{
			name: "Read record with multiple sections",
			args: args{
				&futureBuffer{
							filename:"testdata/multiSection/section_01.txt",
							debugSkipper:false,
						},
			},
			wantRecord: &Record{
				Id:          "26bc3c6f",
				RequestBody: []string{"Teststring1"},
				AuditHeader: &SectionAAuditHeader{
					timestamp:       time.Date(2018, time.October, 8, 0, 0, 1, 0, time.FixedZone("", 0)),
					transactionID:   "W7qB4cCoFIQAAHtbutUAAAFI",
					sourceIP:        net.ParseIP("92.38.32.36"),
					sourcePort:      36354,
					destinationIP:   net.ParseIP("192.168.20.132"),
					destinationPort: 443,
				},
				RequestHeader: &SectionBRequestHeader{
					Protocol: "HTTP/1.1",
					Method:   "POST",
					Path:     "/callback/auth/context/pageview/v1.0",
					Header: &map[string]string{
						"Accept":       "*/*",
						"Content-Type": "application/json",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Read record with following recordf",
			args: args{
				&futureBuffer{
					filename:"testdata/multiSection/section_01_with_following_section.txt",
					debugSkipper:false,
	},
	},
			wantRecord: &Record{
				Id:          "26bc3c6f",
				RequestBody: []string{"Teststring1"},
				AuditHeader: &SectionAAuditHeader{
					timestamp:       time.Date(2018, time.October, 8, 0, 0, 1, 0, time.FixedZone("", 0)),
					transactionID:   "W7qB4cCoFIQAAHtbutUAAAFI",
					sourceIP:        net.ParseIP("92.38.32.36"),
					sourcePort:      36354,
					destinationIP:   net.ParseIP("192.168.20.132"),
					destinationPort: 443,
				},
				RequestHeader: &SectionBRequestHeader{
					Protocol: "HTTP/1.1",
					Method:   "POST",
					Path:     "/callback/auth/context/pageview/v1.0",
					Header: &map[string]string{
						"Accept":       "*/*",
						"Content-Type": "application/json",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Read second record",
			args: args{
				&futureBuffer{
					filename:"testdata/multiSection/read_second_record.txt",
					debugSkipper:false,
	},
	},
			wantRecord: &Record{
				Id:          "26bc3c6f",
				RequestBody: []string{"Teststring1"},
				AuditHeader: &SectionAAuditHeader{
					timestamp:       time.Date(2018, time.October, 8, 0, 0, 1, 0, time.FixedZone("", 0)),
					transactionID:   "W7qB4cCoFIQAAHtbutUAAAFI",
					sourceIP:        net.ParseIP("92.38.32.36"),
					sourcePort:      36354,
					destinationIP:   net.ParseIP("192.168.20.132"),
					destinationPort: 443,
				},
				RequestHeader: &SectionBRequestHeader{
					Protocol: "HTTP/1.1",
					Method:   "POST",
					Path:     "/callback/auth/context/pageview/v1.0",
					Header: &map[string]string{
						"Accept":       "*/*",
						"Content-Type": "application/json",
					},
				},
			},
			wantErr:  false,
			jumpOver: 1,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := tt.args.reader.create()
			for i := 0; i < tt.jumpOver; i++ {
				ReadSingleRecord(reader)
			}
			gotRecord, err := ReadSingleRecord(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadSingleRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRecord, tt.wantRecord) {
				t.Errorf("ReadSingleRecord() =\n is   %#v,\n want %#v", gotRecord, tt.wantRecord)
				if !reflect.DeepEqual(gotRecord.Id, tt.wantRecord.Id) {
					t.Errorf("ReadSingleRecord.Id() =\n is   %#v,\n want %#v", gotRecord.Id, tt.wantRecord.Id)
				}
				if !reflect.DeepEqual(gotRecord.AuditHeader, tt.wantRecord.AuditHeader) {
					t.Errorf("ReadSingleRecord.AuditHeader() =\n is   %#v,\n want %#v", gotRecord.AuditHeader, tt.wantRecord.AuditHeader)
					t.Errorf("%#v", gotRecord.AuditHeader.timestamp.Location())
				}
				if !reflect.DeepEqual(gotRecord.RequestHeader, tt.wantRecord.RequestHeader) {
					t.Errorf("ReadSingleRecord.RequestHeader() =\n is   %#v,\n want %#v", gotRecord.RequestHeader, tt.wantRecord.RequestHeader)
				}
				if !reflect.DeepEqual(gotRecord.RequestBody, tt.wantRecord.RequestBody) {
					t.Errorf("ReadSingleRecord.RequestBody() =\n is   %#v,\n want %#v", gotRecord.RequestBody, tt.wantRecord.RequestBody)
				}
			}
		})
	}
}

func TestRecord_ReadSection(t *testing.T) {
	type fields struct {
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
	type args struct {
		reader *readBuffer
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Record{
				Id:                          tt.fields.Id,
				AuditHeader:                 tt.fields.AuditHeader,
				RequestHeader:               tt.fields.RequestHeader,
				RequestBody:                 tt.fields.RequestBody,
				IntendedResponseHeader:      tt.fields.IntendedResponseHeader,
				IntendedResponseBody:        tt.fields.IntendedResponseBody,
				ResponseHeader:              tt.fields.ResponseHeader,
				ResponseBody:                tt.fields.ResponseBody,
				AuditLogTrailer:             tt.fields.AuditLogTrailer,
				ReducedMultipartRequestBody: tt.fields.ReducedMultipartRequestBody,
				MultipartFilesInformation:   tt.fields.MultipartFilesInformation,
				MatchedRulesInformation:     tt.fields.MatchedRulesInformation,
				AuditLogFooter:              tt.fields.AuditLogFooter,
			}
			if err := r.ReadSection(tt.args.reader); (err != nil) != tt.wantErr {
				t.Errorf("Record.ReadSection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseAuditLogFooter(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionZAuditLogFooter
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseAuditLogFooter(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuditLogFooter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseAuditLogFooter() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseMatchedRulesInformation(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionKMatchedRuleInformation
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseMatchedRulesInformation(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMatchedRulesInformation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseMatchedRulesInformation() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseMultipartFilesInformation(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionJMultipartFileInformation
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseMultipartFilesInformation(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMultipartFilesInformation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseMultipartFilesInformation() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseReducedMultipartRequestBody(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionIReducedMultipartRequestBody
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseReducedMultipartRequestBody(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReducedMultipartRequestBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseReducedMultipartRequestBody() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseAuditLogTrailer(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionHAuditLogTrailer
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseAuditLogTrailer(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuditLogTrailer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseAuditLogTrailer() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseResponseBody(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection []string
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseResponseBody(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponseBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseResponseBody() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseResponseHeader(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionFResponseHeaders
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseResponseHeader(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponseHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseResponseHeader() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseIntendedResponseBody(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionEIntendedResponseBody
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseIntendedResponseBody(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIntendedResponseBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseIntendedResponseBody() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseIntendedResponseHeader(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionDIntendedResponseHeader
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseIntendedResponseHeader(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIntendedResponseHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseIntendedResponseHeader() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseRequestBody(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name            string
		args            args
		wantRequestBody []string
		wantErr         bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRequestBody, err := parseRequestBody(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRequestBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRequestBody, tt.wantRequestBody) {
				t.Errorf("parseRequestBody() = %v, want %v", gotRequestBody, tt.wantRequestBody)
			}
		})
	}
}

func Test_parseRequestHeader(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionBRequestHeader
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseRequestHeader(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRequestHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseRequestHeader() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_parseAuditHeader(t *testing.T) {
	type args struct {
		body []string
	}
	tests := []struct {
		name        string
		args        args
		wantSection *SectionAAuditHeader
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSection, err := parseAuditHeader(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuditHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSection, tt.wantSection) {
				t.Errorf("parseAuditHeader() = %v, want %v", gotSection, tt.wantSection)
			}
		})
	}
}

func Test_isSectionDefinition(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name        string
		args        args
		wantSuccess bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSuccess := isSectionDefinition(tt.args.line); gotSuccess != tt.wantSuccess {
				t.Errorf("isSectionDefinition() = %v, want %v", gotSuccess, tt.wantSuccess)
			}
		})
	}
}

func TestRecordReader_Iter(t *testing.T) {
	tests := []struct {
		name   string
		filename string
		entries int
		skipping int
		err bool
		debugSkipper bool
	}{
		{
			name: "Iterating over 3 records.",
			filename: "testdata/multiSection/3_records.txt",
			entries: 3,
			skipping:0,
			err: false,
			debugSkipper: false,
		},
		{
			name: "Iterating over real live records 31 18.",
			filename: "testdata/multiSection/hhweb31_track4j_post_log.20190518",
			entries: 192504,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 31 19.",
			filename: "testdata/multiSection/hhweb31_track4j_post_log.20190519",
			entries: 195509,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 32 18.",
			filename: "testdata/multiSection/hhweb32_track4j_post_log.20190518",
			entries: 192504,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 32 19.",
			filename: "testdata/multiSection/hhweb32_track4j_post_log.20190519",
			entries: 195509,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 41 18.",
			filename: "testdata/multiSection/hhweb41_track4j_post_log.20190518",
			entries: 192504,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 41 19.",
			filename: "testdata/multiSection/hhweb41_track4j_post_log.20190519",
			entries: 195509,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 42 18.",
			filename: "testdata/multiSection/hhweb42_track4j_post_log.20190518",
			entries: 192504,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		{
			name: "Iterating over real live records 42 19.",
			filename: "testdata/multiSection/hhweb42_track4j_post_log.20190519",
			entries: 195509,
			skipping:0,
			err: false,
			debugSkipper:true,
		},
		// hhweb31_track4j_post_log.20181008
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := CreateRecordReader(tt.filename, tt.debugSkipper)
			if err != nil && !tt.err {
				t.Errorf("Error not wanted, got error = %v", err)
			}
			for i := 0; i < tt.skipping; i++ {
				r.Next()
			}
			i := 0
			for range r.IterLossy() {
				i++
			}
			if i != tt.entries {
				t.Errorf("RecordReader.IterLossy(). Got %v, elements expected %v", i, tt.entries)
				t.Errorf("Runner; %#v", r)
				t.Errorf("Runner.err; %#v", r.Err)
			}
		})
	}
}
