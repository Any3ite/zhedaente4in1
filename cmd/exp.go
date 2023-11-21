package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"source/cmd/vulnerable"
)

var targets string
var proxyAddr string
var expCmd = &cobra.Command{
	Use:   "exp",
	Short: "攻击模式",
	Long:  " _    ___   ___  _              _              _                  _                             \n| |_ / _ \\ / _ \\| |___      ___| |__   ___  __| | __ _  ___ _ __ | |_ ___        _____  ___ __  \n| __| | | | | | | / __|____|_  / '_ \\ / _ \\/ _` |/ _` |/ _ \\ '_ \\| __/ _ \\_____ / _ \\ \\/ / '_ \\ \n| |_| |_| | |_| | \\__ \\_____/ /| | | |  __/ (_| | (_| |  __/ | | | ||  __/_____|  __/>  <| |_) |\n \\__|\\___/ \\___/|_|___/    /___|_| |_|\\___|\\__,_|\\__,_|\\___|_| |_|\\__\\___|      \\___/_/\\_\\ .__/ \n                                                                                         |_|    \n",
	Run: func(cmd *cobra.Command, args []string) {
		vulnerable.EntPhoneSaveAttaFileWorker("exp", targets, proxyAddr)
		vulnerable.CustomerActionEntPhone("exp", targets, proxyAddr)
		vulnerable.FileUPloadJsp("exp", targets, proxyAddr)
		vulnerable.MachordDocApiFileupload("exp", targets, proxyAddr)
	},
}

func init() {
	rootCmd.AddCommand(expCmd)
	expCmd.Flags().StringVarP(&targets, "target", "t", "", "目标地址")
	expCmd.Flags().StringVarP(&proxyAddr, "proxy", "p", "", "目标地址")
	if err := expCmd.MarkFlagRequired("target"); err != nil {
		fmt.Println(expCmd.Usage())
		os.Exit(0)
	}
}
