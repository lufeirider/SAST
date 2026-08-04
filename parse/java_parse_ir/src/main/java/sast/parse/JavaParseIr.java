package sast.parse;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.InitializerDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.resolution.declarations.ResolvedConstructorDeclaration;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.resolution.declarations.ResolvedReferenceTypeDeclaration;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Emit parse_ir.json from Java sources (JavaParser + SymbolSolver).
 * Schema matches Python parse.models (loaded by parse.parsers.parse_ir).
 *
 * Usage:
 *   java -cp ... sast.parse.JavaParseIr
 *     --root &lt;emitSrcRoot&gt; [--root ...]
 *     [--solver-root &lt;extraTypeRoot&gt; ...]
 *     [--out file|-]
 */
public final class JavaParseIr {

    private JavaParseIr() {}

    public static void main(String[] args) throws Exception {
        List<Path> roots = new ArrayList<>();
        List<Path> solverRoots = new ArrayList<>();
        Path out = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--root" -> roots.add(Path.of(args[++i]).toAbsolutePath().normalize());
                case "--solver-root" -> solverRoots.add(Path.of(args[++i]).toAbsolutePath().normalize());
                case "--out" -> out = Path.of(args[++i]);
                case "-h", "--help" -> {
                    System.err.println(
                            "Usage: --root <dir> [--root ...] [--solver-root <dir> ...] [--out file|-]");
                    return;
                }
                default -> throw new IllegalArgumentException("Unknown arg: " + args[i]);
            }
        }
        if (roots.isEmpty()) {
            throw new IllegalArgumentException("At least one --root is required");
        }

        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver(false));
        for (Path root : roots) {
            if (Files.isDirectory(root)) {
                typeSolver.add(new JavaParserTypeSolver(root));
            }
        }
        for (Path root : solverRoots) {
            if (Files.isDirectory(root)) {
                typeSolver.add(new JavaParserTypeSolver(root));
            }
        }

        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        ParserConfiguration config = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)
                .setSymbolResolver(symbolSolver);
        StaticJavaParser.setConfiguration(config);

        // Only emit IR for --root trees (solver-root is classpath only)
        List<Path> javaFiles = new ArrayList<>();
        for (Path root : roots) {
            try (Stream<Path> walk = Files.walk(root)) {
                walk.filter(p -> p.toString().endsWith(".java"))
                        .filter(Files::isRegularFile)
                        .sorted()
                        .forEach(javaFiles::add);
            }
        }

        List<Map<String, Object>> files = new ArrayList<>();
        int errors = 0;
        for (Path file : javaFiles) {
            try {
                files.add(parseFile(file, roots));
            } catch (Exception e) {
                errors++;
                System.err.println("WARN parse failed: " + file + " :: " + e.getMessage());
            }
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("files", files);
        payload.put("file_count", files.size());
        payload.put("error_count", errors);

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        String json = gson.toJson(payload);
        if (out == null || out.toString().equals("-")) {
            System.out.println(json);
        } else {
            Files.writeString(out, json, StandardCharsets.UTF_8);
        }
    }

    private static Map<String, Object> parseFile(Path file, List<Path> roots) throws IOException {
        CompilationUnit cu = StaticJavaParser.parse(file);
        String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
        List<String> imports = cu.findAll(ImportDeclaration.class).stream()
                .map(ImportDeclaration::getNameAsString)
                .collect(Collectors.toList());

        List<Map<String, Object>> types = new ArrayList<>();
        for (TypeDeclaration<?> td : cu.getTypes()) {
            collectTypes(td, pkg, file.toString(), types);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("path", file.toString());
        out.put("language", "java");
        out.put("package", pkg);
        out.put("imports", imports);
        out.put("types", types);
        return out;
    }

    /** Top-level + nested classes/interfaces/enums (needed for Map.Entry / MapEntry gadgets). */
    private static void collectTypes(
            TypeDeclaration<?> td, String pkg, String filePath, List<Map<String, Object>> out) {
        out.add(extractType(td, pkg, filePath));
        for (TypeDeclaration<?> nested : td.findAll(TypeDeclaration.class)) {
            if (nested == td) {
                continue;
            }
            // only direct nested members (avoid double-walk of deeper nests via findAll)
            if (nested.getParentNode().isPresent() && nested.getParentNode().get() == td) {
                collectTypes(nested, pkg, filePath, out);
            }
        }
    }

    private static Map<String, Object> extractType(TypeDeclaration<?> td, String pkg, String filePath) {
        String name = td.getNameAsString();
        String qn = pkg.isEmpty() ? name : pkg + "." + name;
        try {
            ResolvedReferenceTypeDeclaration resolved = td.resolve();
            qn = resolved.getQualifiedName();
        } catch (Exception ignored) {
            // Nested types: Outer.Inner when resolve fails
            if (td.isNestedType()) {
                List<String> parts = new ArrayList<>();
                Node cur = td;
                while (cur instanceof TypeDeclaration<?> tdn) {
                    parts.add(0, tdn.getNameAsString());
                    cur = cur.getParentNode().orElse(null);
                }
                String nested = String.join(".", parts);
                qn = pkg.isEmpty() ? nested : pkg + "." + nested;
            }
        }

        String kind = "class";
        List<String> extendsList = new ArrayList<>();
        List<String> implementsList = new ArrayList<>();
        if (td instanceof ClassOrInterfaceDeclaration c) {
            kind = c.isInterface() ? "interface" : "class";
            for (ClassOrInterfaceType t : c.getExtendedTypes()) {
                extendsList.add(resolveTypeName(t));
            }
            for (ClassOrInterfaceType t : c.getImplementedTypes()) {
                implementsList.add(resolveTypeName(t));
            }
        } else if (td instanceof EnumDeclaration) {
            kind = "enum";
        }

        List<Map<String, Object>> fields = new ArrayList<>();
        for (FieldDeclaration fd : td.getFields()) {
            boolean isStatic = fd.isStatic();
            boolean isTransient = fd.isTransient();
            boolean isFinal = fd.isFinal();
            String typeName = fd.getElementType().asString();
            String resolvedType = "";
            try {
                ResolvedType rt = fd.getElementType().resolve();
                if (rt.isArray()) {
                    resolvedType = rt.asArrayType().describe();
                } else if (rt.isReferenceType()) {
                    resolvedType = rt.asReferenceType().getQualifiedName();
                } else {
                    resolvedType = rt.describe();
                }
            } catch (Exception ignored) {
                // keep typeName
            }
            for (VariableDeclarator v : fd.getVariables()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("name", v.getNameAsString());
                f.put("type_name", typeName);
                f.put("resolved_type", resolvedType);
                f.put("is_static", isStatic);
                f.put("is_transient", isTransient);
                f.put("is_final", isFinal);
                f.put("start_line", lineOf(fd));
                fields.add(f);
            }
        }

        List<Map<String, Object>> methods = new ArrayList<>();
        for (MethodDeclaration md : td.getMethods()) {
            methods.add(extractCallable(md, qn));
        }
        for (ConstructorDeclaration cd : td.getConstructors()) {
            methods.add(extractCallable(cd, qn));
        }
        // Static initializers hold Class.forName / getMethod constants used by reflection.
        for (BodyDeclaration<?> member : td.getMembers()) {
            if (member instanceof InitializerDeclaration init && init.isStatic()) {
                methods.add(extractStaticInitializer(init, qn));
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", name);
        out.put("qualified_name", qn);
        out.put("kind", kind);
        out.put("package", pkg);
        out.put("file_path", filePath);
        out.put("extends", extendsList);
        out.put("implements", implementsList);
        out.put("methods", methods);
        out.put("fields", fields);
        out.put("start_line", lineOf(td));
        out.put("end_line", endLineOf(td));
        return out;
    }

    private static Map<String, Object> extractStaticInitializer(
            InitializerDeclaration init, String ownerQn) {
        String methodQn = ownerQn + "#<clinit>()";
        List<Map<String, Object>> callSites = new ArrayList<>();
        List<String> calls = new ArrayList<>();
        Set<String> seenCalls = new LinkedHashSet<>();

        for (MethodCallExpr call : init.findAll(MethodCallExpr.class)) {
            Map<String, Object> cs = extractMethodCall(call);
            callSites.add(cs);
            String key = String.valueOf(cs.get("callee_name"));
            String resolved = String.valueOf(cs.getOrDefault("resolved_qn", ""));
            if (!resolved.isEmpty() && !"null".equals(resolved)) {
                key = resolved;
            }
            if (seenCalls.add(key)) {
                calls.add(String.valueOf(cs.get("callee_name")));
            }
        }
        for (ObjectCreationExpr oc : init.findAll(ObjectCreationExpr.class)) {
            Map<String, Object> cs = extractCtorCall(oc);
            callSites.add(cs);
            String key = String.valueOf(cs.get("callee_name"));
            if (seenCalls.add(key)) {
                calls.add(key);
            }
        }

        List<Map<String, Object>> assignments = new ArrayList<>();
        for (VariableDeclarator v : init.findAll(VariableDeclarator.class)) {
            if (v.getInitializer().isEmpty()) continue;
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("lhs", v.getNameAsString());
            a.put("rhs", v.getInitializer().get().toString());
            a.put("line", lineOf(v));
            assignments.add(a);
        }
        for (AssignExpr ae : init.findAll(AssignExpr.class)) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("lhs", normalizeLhs(ae.getTarget().toString()));
            a.put("rhs", ae.getValue().toString());
            a.put("line", lineOf(ae));
            assignments.add(a);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", "<clinit>");
        out.put("qualified_name", methodQn);
        out.put("return_type", "void");
        out.put("is_constructor", false);
        out.put("parameters", List.of());
        out.put("call_sites", callSites);
        out.put("calls", calls);
        out.put("assignments", assignments);
        out.put("start_line", lineOf(init));
        out.put("end_line", endLineOf(init));
        return out;
    }

    private static Map<String, Object> extractCallable(CallableDeclaration<?> cd, String ownerQn) {
        boolean isCtor = cd instanceof ConstructorDeclaration;
        String name = cd.getNameAsString();

        List<Map<String, Object>> params = new ArrayList<>();
        int idx = 0;
        List<String> paramTypeSimple = new ArrayList<>();
        for (Parameter p : cd.getParameters()) {
            Map<String, Object> pi = new LinkedHashMap<>();
            String t = p.getType().asString();
            pi.put("name", p.getNameAsString());
            pi.put("type_name", t);
            pi.put("index", idx++);
            params.add(pi);
            paramTypeSimple.add(simpleName(t));
        }

        String methodQn = ownerQn + "#" + (isCtor ? ownerQn.substring(ownerQn.lastIndexOf('.') + 1) : name)
                + "(" + String.join(",", paramTypeSimple) + ")";
        if (isCtor) {
            String simple = ownerQn.contains(".") ? ownerQn.substring(ownerQn.lastIndexOf('.') + 1) : ownerQn;
            methodQn = ownerQn + "#" + simple + "(" + String.join(",", paramTypeSimple) + ")";
        }

        // Prefer SymbolSolver signature when available
        try {
            if (cd instanceof MethodDeclaration md) {
                ResolvedMethodDeclaration r = md.resolve();
                methodQn = toMethodQn(r);
                name = r.getName();
            } else if (cd instanceof ConstructorDeclaration ctor) {
                ResolvedConstructorDeclaration r = ctor.resolve();
                methodQn = toConstructorQn(r);
            }
        } catch (Exception ignored) {
        }

        String returnType = "";
        if (cd instanceof MethodDeclaration md) {
            returnType = md.getType().asString();
        }

        List<Map<String, Object>> callSites = new ArrayList<>();
        List<String> calls = new ArrayList<>();
        Set<String> seenCalls = new LinkedHashSet<>();

        for (MethodCallExpr call : cd.findAll(MethodCallExpr.class)) {
            Map<String, Object> cs = extractMethodCall(call);
            callSites.add(cs);
            String key = String.valueOf(cs.get("callee_name"));
            String resolved = String.valueOf(cs.getOrDefault("resolved_qn", ""));
            if (!resolved.isEmpty() && !"null".equals(resolved)) {
                key = resolved;
            }
            if (seenCalls.add(key)) {
                calls.add(String.valueOf(cs.get("callee_name")));
            }
        }
        for (ObjectCreationExpr oc : cd.findAll(ObjectCreationExpr.class)) {
            Map<String, Object> cs = extractCtorCall(oc);
            callSites.add(cs);
            String key = String.valueOf(cs.get("callee_name"));
            if (seenCalls.add(key)) {
                calls.add(key);
            }
        }

        List<Map<String, Object>> assignments = new ArrayList<>();
        for (VariableDeclarator v : cd.findAll(VariableDeclarator.class)) {
            if (v.getInitializer().isEmpty()) continue;
            // skip field-level if somehow nested wrong — only method body
            if (!isUnder(v, cd)) continue;
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("lhs", v.getNameAsString());
            a.put("rhs", v.getInitializer().get().toString());
            a.put("line", lineOf(v));
            assignments.add(a);
        }
        for (AssignExpr ae : cd.findAll(AssignExpr.class)) {
            if (!isUnder(ae, cd)) continue;
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("lhs", normalizeLhs(ae.getTarget().toString()));
            a.put("rhs", ae.getValue().toString());
            a.put("line", lineOf(ae));
            assignments.add(a);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", isCtor
                ? (ownerQn.contains(".") ? ownerQn.substring(ownerQn.lastIndexOf('.') + 1) : ownerQn)
                : name);
        out.put("qualified_name", methodQn);
        out.put("return_type", returnType);
        out.put("parameters", params);
        out.put("start_line", lineOf(cd));
        out.put("end_line", endLineOf(cd));
        out.put("calls", calls);
        out.put("call_sites", callSites);
        out.put("assignments", assignments);
        return out;
    }

    private static Map<String, Object> extractMethodCall(MethodCallExpr call) {
        Map<String, Object> cs = new LinkedHashMap<>();
        cs.put("callee_name", call.getNameAsString());
        cs.put("receiver", call.getScope().map(Object::toString).orElse(""));
        cs.put("arguments", call.getArguments().stream().map(Object::toString).collect(Collectors.toList()));
        cs.put("line", lineOf(call));
        cs.put("is_constructor", false);
        String resolvedQn = "";
        try {
            ResolvedMethodDeclaration r = call.resolve();
            resolvedQn = toMethodQn(r);
        } catch (Exception ignored) {
        }
        cs.put("resolved_qn", resolvedQn);
        return cs;
    }

    private static Map<String, Object> extractCtorCall(ObjectCreationExpr oc) {
        Map<String, Object> cs = new LinkedHashMap<>();
        String typeName = oc.getType().asString();
        cs.put("callee_name", simpleName(typeName));
        cs.put("receiver", "");
        cs.put("arguments", oc.getArguments().stream().map(Object::toString).collect(Collectors.toList()));
        cs.put("line", lineOf(oc));
        cs.put("is_constructor", true);
        String resolvedQn = "";
        try {
            ResolvedConstructorDeclaration r = oc.resolve();
            resolvedQn = toConstructorQn(r);
        } catch (Exception ignored) {
            try {
                ResolvedType t = oc.getType().resolve();
                if (t.isReferenceType()) {
                    String tqn = t.asReferenceType().getQualifiedName();
                    resolvedQn = tqn + "#" + simpleName(tqn) + "(" + oc.getArguments().size() + " args)";
                }
            } catch (Exception ignored2) {
            }
        }
        cs.put("resolved_qn", resolvedQn);
        return cs;
    }

    private static String toMethodQn(ResolvedMethodDeclaration r) {
        String owner = r.declaringType().getQualifiedName();
        List<String> params = new ArrayList<>();
        for (int i = 0; i < r.getNumberOfParams(); i++) {
            params.add(simpleName(describeParam(r, i)));
        }
        return owner + "#" + r.getName() + "(" + String.join(",", params) + ")";
    }

    private static String toConstructorQn(ResolvedConstructorDeclaration r) {
        String owner = r.declaringType().getQualifiedName();
        String simple = simpleName(owner);
        List<String> params = new ArrayList<>();
        for (int i = 0; i < r.getNumberOfParams(); i++) {
            try {
                params.add(simpleName(r.getParam(i).describeType()));
            } catch (Exception e) {
                params.add("?");
            }
        }
        return owner + "#" + simple + "(" + String.join(",", params) + ")";
    }

    private static String describeParam(ResolvedMethodDeclaration r, int i) {
        try {
            return r.getParam(i).describeType();
        } catch (Exception e) {
            try {
                return r.getParam(i).getType().describe();
            } catch (Exception e2) {
                return "?";
            }
        }
    }

    private static String resolveTypeName(ClassOrInterfaceType t) {
        try {
            ResolvedType rt = t.resolve();
            if (rt.isReferenceType()) {
                return rt.asReferenceType().getQualifiedName();
            }
            return rt.describe();
        } catch (Exception e) {
            return t.getNameWithScope();
        }
    }

    private static String simpleName(String type) {
        if (type == null || type.isEmpty()) return type;
        String t = type.replace("[]", "");
        int gen = t.indexOf('<');
        if (gen >= 0) t = t.substring(0, gen);
        int dot = t.lastIndexOf('.');
        String base = dot >= 0 ? t.substring(dot + 1) : t;
        if (type.endsWith("[]")) {
            // restore array dims
            int dims = type.length() - type.replace("[]", "").length();
            // rough
            return base + "[]".repeat(Math.max(1, type.split("\\[]", -1).length - 1));
        }
        return base;
    }

    private static String normalizeLhs(String lhs) {
        lhs = lhs.trim();
        if (lhs.startsWith("this.")) return lhs.substring(5);
        return lhs;
    }

    private static boolean isUnder(Node node, Node ancestor) {
        Optional<Node> p = node.getParentNode();
        while (p.isPresent()) {
            if (p.get() == ancestor) return true;
            p = p.get().getParentNode();
        }
        return false;
    }

    private static int lineOf(Node n) {
        return n.getBegin().map(p -> p.line).orElse(0);
    }

    private static int endLineOf(Node n) {
        return n.getEnd().map(p -> p.line).orElse(lineOf(n));
    }
}
