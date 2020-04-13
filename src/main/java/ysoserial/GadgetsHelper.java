package ysoserial;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import ysoserial.payloads.*;

/**
 * @author threedr3am
 */
public class GadgetsHelper {

    private static final Map<String, Set<Class<? extends ObjectPayload>>> gadgets = new HashMap<>();

    static {
        Set<Class<? extends ObjectPayload>> cmds = new HashSet<>();
        cmds.add(CommonsBeanutils1.class);
        cmds.add(CommonsCollections8.class);
        cmds.add(CommonsCollections9.class);
        cmds.add(CommonsCollections10.class);
        cmds.add(CommonsCollections11.class);
        cmds.add(Jdk7u21.class);
        gadgets.put("CMD", cmds);

        Set<Class<? extends ObjectPayload>> jar = new HashSet<>();
        jar.add(CommonsCollections3ForLoadJar.class);
        jar.add(CommonsCollections5ForLoadJar.class);
        jar.add(CommonsCollections6ForLoadJar.class);
        gadgets.put("JAR", jar);

        Set<Class<? extends ObjectPayload>> codebase = new HashSet<>();
        codebase.add(C3P0.class);
        gadgets.put("CODEBASE", codebase);
    }

    public static Set<Class<? extends ObjectPayload>> get(String type) {
        return gadgets.get(type);
    }
}
