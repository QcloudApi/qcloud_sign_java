/*=============================================================================
#
#     FileName: QcloudSign.java
#         Desc: Qcloud 签名调试工具
#
#       Author: gavinyao
#        Email: gavinyao@tencent.com
#
#      Created: 2014-12-19 11:30:04
#      Version: 0.0.1
#      History:
#               0.0.1 | gavinyao | 2014-12-19 11:30:04 | initialization
#
=============================================================================*/
import javax.crypto.Mac;
import java.util.TreeMap;

import java.io.IOException;

import sun.misc.BASE64Encoder;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;

/**
 * @brief 腾讯云API 签名工具
 * @author gavinyao@tencent.com
 * @date 2014-08-13 20:48:11
 */
public class QcloudSign {

    // 编码方式
    private static final String CONTENT_CHARSET = "UTF-8";

    // HMAC算法
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    /**
     * @brief 签名
     * @author gavinyao@tencent.com
     * @date 2014-08-13 21:07:27
     *
     * @param signStr 被加密串
     * @param secret 加密密钥
     *
     * @return
     */
    public static String sign(String signStr, String secret) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {

        String sig = null;
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(CONTENT_CHARSET), mac.getAlgorithm());

        mac.init(secretKey);
        byte[] hash = mac.doFinal(signStr.getBytes(CONTENT_CHARSET));

        // base64
        sig = new String(new BASE64Encoder().encode(hash).getBytes());

        return sig;
    }

    public static String makeSignPlainText(TreeMap<String, Object> requestParams) {

        return makeSignPlainText(requestParams, "GET", "cvm.api.qcloud.com", "/v2/index.php");
    }
    public static String makeSignPlainText(TreeMap<String, Object> requestParams,
            String requestMethod) {

        return makeSignPlainText(requestParams, requestMethod, "cvm.api.qcloud.com", "/v2/index.php");
    }

    public static String makeSignPlainText(TreeMap<String, Object> requestParams,
            String requestMethod, String requestHost) {

        return makeSignPlainText(requestParams, requestMethod, requestHost, "/v2/index.php");
    }
    public static String makeSignPlainText(TreeMap<String, Object> requestParams,
            String requestMethod, String requestHost, String requestPath) {

        String retStr = "";
        retStr += requestMethod;
        retStr += requestHost;
        retStr += requestPath;
        retStr += _buildParamStr(requestParams);

        return retStr;
    }

    protected static String _buildParamStr(TreeMap<String, Object> requestParams) {
        return _buildParamStr(requestParams, "GET");
    }

    protected static String _buildParamStr(TreeMap<String, Object> requestParams, String requestMethod) {

        String retStr = "";
        for(String key: requestParams.keySet()) {
            if (key.equals("Signature")) {
                continue;
            }
            if (retStr.isEmpty()) {
                retStr += '?';
            } else {
                retStr += '&';
            }
            retStr += key + '=' + requestParams.get(key).toString();

        }

        return retStr;
    }
}
