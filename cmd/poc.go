package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"source/cmd/vulnerable"
)

var target string
var proxy string
var pocCmd = &cobra.Command{
	Use:   "poc",
	Short: "测试状态",
	Long:  " _    ___   ___  _              _              _                  _                              \n| |_ / _ \\ / _ \\| |___      ___| |__   ___  __| | __ _  ___ _ __ | |_ ___       _ __   ___   ___ \n| __| | | | | | | / __|____|_  / '_ \\ / _ \\/ _` |/ _` |/ _ \\ '_ \\| __/ _ \\_____| '_ \\ / _ \\ / __|\n| |_| |_| | |_| | \\__ \\_____/ /| | | |  __/ (_| | (_| |  __/ | | | ||  __/_____| |_) | (_) | (__ \n \\__|\\___/ \\___/|_|___/    /___|_| |_|\\___|\\__,_|\\__,_|\\___|_| |_|\\__\\___|     | .__/ \\___/ \\___|\n                                                                               |_|               \n",
	Run: func(cmd *cobra.Command, args []string) {
		vulnerable.EntPhoneSaveAttaFileWorker("poc", target, proxy)
		vulnerable.CustomerActionEntPhone("poc", target, proxyAddr)
		vulnerable.FileUPloadJsp("poc", target, proxyAddr)
		vulnerable.MachordDocApiFileupload("poc", target, proxyAddr)
	},
}

func init() {
	rootCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&target, "target", "t", "", "目标地址")
	pocCmd.Flags().StringVarP(&proxy, "proxy", "p", "", "代理地址")
	err := pocCmd.MarkFlagRequired("target")
	if err != nil {
		fmt.Println(pocCmd.Usage())
	}

}
