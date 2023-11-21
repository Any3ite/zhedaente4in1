package vulnerable

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func HttpCli(proxyAddress string) *http.Client {

	cli := &http.Client{}
	transPortConfig := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}, Proxy: http.ProxyURL(nil)}
	if proxyAddress == "" {
		cli.Transport = transPortConfig
		return cli
	} else {
		parse, _ := url.Parse(proxyAddress)
		if parse.Scheme != "http" && parse.Scheme != "socks5" {
			fmt.Println("Not Allowed Proxy")
			os.Exit(0)
		}
		if parse.Port() <= strconv.Itoa(0) || parse.Port() > strconv.Itoa(65535) {
			fmt.Println("Invalid Proxy Port")
			os.Exit(0)
		}
		cli.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
				MinVersion: tls.VersionTLS10,
				MaxVersion: tls.VersionTLS13},
			Proxy: http.ProxyURL(parse)}
		cli.Timeout = time.Second * 15
		return cli
	}
}
