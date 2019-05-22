// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"github.com/Fjolnir-Dvorak/modsecParser/modsecure"
	"os"
	"path"
	"strconv"

	"github.com/spf13/cobra"
)


var (
	sortUrls      bool
	sortStatus    bool
	sortMethod    bool
	fileList      []string
	outDirectory  string
	fileMap = make(map[string]*os.File)
	lossyMode     bool
	persistErrors bool
)

// parseCmd represents the parse command
var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: doParseAction,
}

func init() {
	RootCmd.AddCommand(parseCmd)


	parseCmd.Flags().BoolVarP(&sortUrls, "sortByUrls", "u", false, "sorts by urls")
	parseCmd.Flags().BoolVarP(&sortStatus, "sortByStatusCodes", "s", false, "sorts by HTTP status code")
	parseCmd.Flags().BoolVarP(&sortMethod, "sortByMethod", "m", false, "sorts")
	parseCmd.Flags().StringArrayVarP(&fileList, "files", "f", nil, "files to parse")
	parseCmd.MarkFlagRequired("files")
	parseCmd.Flags().StringVarP(&outDirectory, "out", "o", "out/", "output directory")
	parseCmd.MarkFlagRequired("out")
	parseCmd.Flags().BoolVarP(&lossyMode, "lossyMode", "l", false, "Turnes on lossy mode. Default stops parsing on error")
	parseCmd.Flags().BoolVarP(&persistErrors, "persistErrors", "p", false, "Persists parse errors on lossy mode")
}

func doParseAction(cmd *cobra.Command, args []string) {
	defer closeFileMap()
	for _, elem := range fileList {
		reader, err := modsecure.CreateRecordReader(elem, false)
		if err != nil {
			panic(err)
		}
		filename := path.Base(elem)
		if lossyMode {
			for recordAndRaw := range reader.IterLossy() {
				if recordAndRaw.Record != nil {
					saveRecord(recordAndRaw.Record, filename)
				} else {
					saveError(recordAndRaw.Raw, filename)
				}
			}
		} else {
			for record := range reader.Iter() {
				saveRecord(record, filename)
			}
		}
	}
}

func saveError(payload string, filename string) {
	savePath := composeErrorPath(outDirectory)
	appendToFile(savePath, filename, []byte(payload))
}

func saveRecord(record *modsecure.Record, filename string) {
	statusCode := record.ResponseHeader.Status
	requestPath := record.RequestHeader.Path
	requestMethod := record.RequestHeader.Method

	savePath := composePath(outDirectory, int(statusCode), requestMethod, requestPath, sortStatus, sortMethod, sortUrls)
	payload, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	appendToFile(savePath, filename, payload)
}

func composeErrorPath(basePath string) (string) {
	return path.Join(basePath, "error")
}

func composePath(basePath string, statusCode int, requestMethod string, requestPath string, useStatusCode, useRequestMethod, useRequestPath bool) (returnPath string){
	returnPath = basePath
	if useStatusCode {
		returnPath = path.Join(returnPath, strconv.Itoa(statusCode))
	}
	if useRequestMethod {
		returnPath = path.Join(returnPath, requestMethod)
	}
	if useRequestPath {
		returnPath = path.Join(returnPath, requestPath)
	}
	return returnPath
}

func appendToFile(filepath, filename string, payload []byte) {
	f := getFileHandler(filepath, filename)
	_, err := f.Write(payload)
	f.WriteString("\n")
	if err != nil {
		panic(err)
	}
}
func getFileHandler(filepath, filename string) (f *os.File) {
	fullName := path.Join(filepath, filename)
	f, ok := fileMap[fullName]
	if ok {
		return f
	}
	os.MkdirAll(filepath, os.ModePerm)
	f, err := os.OpenFile(fullName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	fileMap[fullName] = f
	return f
}

func closeFileMap() {
	for _, f := range fileMap {
		f.Close()
	}
}
