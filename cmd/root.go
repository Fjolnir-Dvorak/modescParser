// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
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
	"fmt"
	"github.com/Fjolnir-Dvorak/modsecParser/modsecure"
	"os"
	"path"
	"strconv"

	"github.com/Fjolnir-Dvorak/environ"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"path/filepath"
)

const (
	VendorName      = "Fjolnir-Dvorak"
	ApplicationName = "modsecParser"
	DefaultConfType = "yaml"
)

var (
	cfgFile      string
	Environ      environ.Environ
	sortUrls     bool
	sortStatus   bool
	sortMethod   bool
	fileList     []string
	outDirectory string
	fileMap = make(map[string]*os.File)
)

var RootCmd = &cobra.Command{
	Use:   ApplicationName,
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: doRootAction,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	Environ = environ.New(VendorName, ApplicationName)
	cobra.OnInitialize(initConfig)

	configFile := filepath.Join(Environ.VarConfigLocal(), ApplicationName+"."+DefaultConfType)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is "+configFile+")")


	RootCmd.Flags().BoolVarP(&sortUrls, "sortByUrls", "u", false, "sorts by urls")
	RootCmd.Flags().BoolVarP(&sortStatus, "sortByStatusCodes", "s", false, "sorts by HTTP status code")
	RootCmd.Flags().BoolVarP(&sortMethod, "sortByMethod", "m", false, "sorts")
	RootCmd.Flags().StringArrayVarP(&fileList, "files", "f", nil, "files to parse")
	RootCmd.MarkFlagRequired("files")
	RootCmd.Flags().StringVarP(&outDirectory, "out", "o", "out/", "output directory")
	RootCmd.MarkFlagRequired("out")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {

		// Search config in Environ.ConfigLocal() directory with name "ApplicationName" (without extension).
		viper.AddConfigPath(Environ.ConfigLocal())
		viper.SetConfigName(ApplicationName)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func doRootAction(cmd *cobra.Command, args []string) {
	defer closeFileMap()
	for _, elem := range fileList {
		reader, err := modsecure.CreateRecordReader(elem, false)
		if err != nil {
			panic(err)
		}
		filename := path.Base(elem)
		for record := range reader.Iter() {
			saveRecord(record, filename)
		}
	}
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