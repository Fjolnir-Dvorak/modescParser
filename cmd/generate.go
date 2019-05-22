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
	"os"
	"github.com/spf13/cobra"
	"github.com/alecthomas/jsonschema"
	"github.com/Fjolnir-Dvorak/modsecParser/modsecure"
)

var (
	jsonSchemaFile string
	bashCompletionFile string
	zshCompletionFile string
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: doGenerateAction,
}

func init() {
	RootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVar(&jsonSchemaFile, "jsonSchema", "", "generates a jsonSchema and persists it into the specified file")
	generateCmd.Flags().StringVar(&bashCompletionFile, "bashCompletion", "", "generates a bash completion script into the specified file")
	generateCmd.Flags().StringVar(&zshCompletionFile, "zshCompletion", "", "generates a zsh completion script into the specified file")
}

func doGenerateAction(cmd *cobra.Command, args []string) {
	if len(bashCompletionFile) > 0 {
		RootCmd.GenBashCompletionFile(bashCompletionFile)
	}
	if len(zshCompletionFile) > 0 {
		RootCmd.GenZshCompletionFile(zshCompletionFile)
	}
	if len(jsonSchemaFile) > 0 {
		schema := jsonschema.Reflect(&modsecure.Record{})
		payload, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			panic(err)
		}
		f, err := os.OpenFile(jsonSchemaFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.Write(payload)
	}
}
