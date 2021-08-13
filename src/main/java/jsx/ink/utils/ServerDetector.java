package jsx.ink.utils;

public class ServerDetector {
    private static ServerDetector _instance = new ServerDetector();
    private Boolean _webLogic;
    public ServerDetector() {
    }
    public static boolean isWebLogic() {
        ServerDetector sd = _instance;
        if (sd._webLogic == null) {
            sd._webLogic = _detect("/weblogic/Server.class");
        }
        return sd._webLogic;
    }


    private static Boolean _detect(String className) {
        try {
            ClassLoader.getSystemClassLoader().loadClass(className);
            return Boolean.TRUE;
        } catch (ClassNotFoundException var4) {
            ServerDetector sd = _instance;
            Class<?> c = sd.getClass();
            return c.getResource(className) != null ? Boolean.TRUE : Boolean.FALSE;
        }
    }

}

