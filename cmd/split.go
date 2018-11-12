// // Copyright © 2018 NAME HERE <EMAIL ADDRESS>
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package cmd

import (
	"log"
	"os"

	"github.com/devopsbrett/pemtools/certbundle"
	"github.com/spf13/cobra"
)

// import (
// 	"bytes"
// 	"crypto/x509"
// 	"encoding/pem"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"time"

// 	"github.com/davecgh/go-spew/spew"

// 	"github.com/alexeyco/simpletable"
// 	"github.com/spf13/cobra"
// )

var expiredDir, outputDir string

// // splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split [pem bundle]",
	Short: "A brief description of your command",
	Args:  cobra.ExactArgs(1),
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]

		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			log.Fatal("Output directory does not exist.")
		}
		if expiredDir != "" {
			if _, err := os.Stat(expiredDir); os.IsNotExist(err) {
				log.Fatal("Expired certificate directory does not exist.")
			}
		}

		cabundle, err := certbundle.BundleFromFile(filename)

		if err != nil {
			log.Fatal(err)
		}

		err = cabundle.OutputPEMFiles(outputDir, expiredDir)
		if err != nil {
			log.Fatal(err)
		}
		// table.SetStyle(simpletable.StyleCompactLite)

	},
}

func init() {
	rootCmd.AddCommand(splitCmd)

	splitCmd.Flags().StringVarP(&outputDir, "output-dir", "o", ".", "Directory to output individual certificate pem files.")
	splitCmd.Flags().StringVar(&expiredDir, "expired-dir", "", "By default expired certs are not written. Setting this will write expired certs to the directory specified")

}
