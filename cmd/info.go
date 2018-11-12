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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/alexeyco/simpletable"
	"github.com/davecgh/go-spew/spew"
	"github.com/devopsbrett/pemtools/cacert"
	"github.com/spf13/cobra"
)

// splitCmd represents the split command
var infoCmd = &cobra.Command{
	Use:   "info [pem bundle]",
	Short: "A brief description of your command",
	Args:  cobra.ExactArgs(1),
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]

		certPEMBlock, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		table := simpletable.New()
		table.Header = &simpletable.Header{
			Cells: []*simpletable.Cell{
				{Align: simpletable.AlignCenter, Text: "CN"},
				{Align: simpletable.AlignCenter, Text: "Issuer"},
				{Align: simpletable.AlignCenter, Text: "Expires"},
			},
		}
		// var blocks [][]byte
		var row []*simpletable.Cell
		emptyCerts := make([]string, 0)
		expiredCerts := 0
		for {
			var certDERBlock *pem.Block
			certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
			if certDERBlock == nil {
				break
			}
			cert, err := cacert.ParseDER(certDERBlock.Bytes)
			if err != nil {
				log.Println(err)
				continue
			}
			if cert.Expired() {
				expiredCerts++
			}
			spew.Dump(string(cert.Certificate.RawSubject))
			spew.Dump(string(cert.Certificate.RawIssuer))
			// if certName = cert.Subject.CommonName; certName == "" {
			// 	certName = cert.Subject.String()
			// 	emptyCerts = append(emptyCerts, spew.Sdump(cert))
			// }

			// fmt.Println(cert.Issuer.ToRDNSequence())

			row = []*simpletable.Cell{
				{Text: formatText(cert.DisplayName, cert.Invalid)},
				{Text: formatText(cert.Certificate.Issuer.CommonName, cert.Invalid)},
				{Text: formatText(cert.Certificate.NotAfter.String(), cert.Invalid)},
			}
			table.Body.Cells = append(table.Body.Cells, row)

			//fmt.Println(certDERBlock.Type)
		}
		// table.SetStyle(simpletable.StyleCompactLite)

		fmt.Println(table.String())
		fmt.Printf("Bundle contained %d expired certs\n", expiredCerts)
		fmt.Printf("Printing %d certificates we got no common name for.\n", len(emptyCerts))
		// for _, c := range emptyCerts {
		// 	fmt.Println(c)
		// }

	},
}

func init() {
	rootCmd.AddCommand(infoCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// splitCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// splitCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
