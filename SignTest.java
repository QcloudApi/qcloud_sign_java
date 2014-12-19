/*=============================================================================
#
#     FileName: SignTest.java
#         Desc: qcloud 签名测试工具
#
#       Author: gavinyao
#        Email: gavinyao@tencent.com
#
#      Created: 2014-12-19 11:29:41
#      Version: 0.0.1
#      History:
#               0.0.1 | gavinyao | 2014-12-19 11:29:41 | initialization
#
=============================================================================*/
import java.net.*;
import java.io.*;
import java.util.Map;
import java.util.TreeMap;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.security.Timestamp;
import javax.net.ssl.*;

public class SignTest {

    // SecretId 和 SecretKey
    private static final String SECRET_ID = "YOUR_SECRET_ID";
    private static final String SECRET_KEY = "YOUR_SECRET_KEY";

    public static void main(String[] args) {

        TreeMap<String, Object> requestParams = new TreeMap<String, Object>();
        requestParams.put("SecretId", SECRET_ID);
        requestParams.put("Region", "gz");
        requestParams.put("Timestamp", System.currentTimeMillis() / 1000);
        Random rand = new Random();
        requestParams.put("Nonce", rand.nextInt(java.lang.Integer.MAX_VALUE));

        requestParams.put("Action", "DescribeInstances");

        String requestMethod = "POST";
        String requestHost = "cvm.api.qcloud.com";
        String requestPath = "/v2/index.php";

        try {
            String plainText = QcloudSign.makeSignPlainText(requestParams, requestMethod, requestHost, requestPath);
            String sign = QcloudSign.sign(plainText, SECRET_KEY);
            System.out.println("原文: " + plainText);
            System.out.println("签名: " + sign);

            if (requestMethod.equals("GET")) {
                requestParams.put("Signature", java.net.URLEncoder.encode(sign, "UTF-8"));
            } else {
                requestParams.put("Signature", sign);
            }

            String retStr = _sendRequest("https://" + requestHost + requestPath, requestParams, requestMethod);
            System.out.println(retStr);

        } catch(Exception e) {
            System.out.println(e);
        }

    }

    protected static String _sendRequest(String url,
            Map<String, Object> requestParams, String requestMethod)
    {
        String result = "";
        BufferedReader in = null;
        String paramStr = "";

        for(String key: requestParams.keySet()) {
            if (!paramStr.isEmpty()) {
                paramStr += '&';
            }
            paramStr += key + '=' + requestParams.get(key).toString();
        }

        try {

            if (requestMethod.equals("GET")) {
                if (url.indexOf('?') > 0)
                {
                    url += '&' + paramStr;
                } else {
                    url += '?' + paramStr;
                }
            }

            URL realUrl = new URL(url);
            URLConnection connection = null;
            if (url.substring(0, 5).toUpperCase().equals("HTTPS")) {
                HttpsURLConnection httpsConn = (HttpsURLConnection)realUrl.openConnection();

                httpsConn.setHostnameVerifier(new HostnameVerifier(){
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });
                connection = httpsConn;
            } else {
                connection = realUrl.openConnection();
            }

            // 设置通用的请求属性
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent",
                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");

            if (requestMethod.equals("POST")) {
                // 发送POST请求必须设置如下两行
                connection.setDoOutput(true);
                connection.setDoInput(true);
                // 获取URLConnection对象对应的输出流
                PrintWriter out = new PrintWriter(connection.getOutputStream());
                // 发送请求参数
                out.print(paramStr);
                // flush输出流的缓冲
                out.flush();
            }

            // 建立实际的连接
            connection.connect();

            // 定义 BufferedReader输入流来读取URL的响应
            in = new BufferedReader(new InputStreamReader(
                    connection.getInputStream()));

            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 使用finally块来关闭输入流
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result;
    }
}

