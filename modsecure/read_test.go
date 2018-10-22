package modsecure

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type futureBuffer struct {
	filename string
}

func (fb futureBuffer) create() (buffer *readBuffer) {
	buffer, err := createBuffer(fb.filename)
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
