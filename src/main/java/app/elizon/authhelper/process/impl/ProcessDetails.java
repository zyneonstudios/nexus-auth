package app.elizon.authhelper.process;

import java.lang.reflect.Executable;
import java.util.HashMap;

public abstract class ProcessDetails {

    public HashMap<String, String> login() { return null;}

    public HashMap<String, String> relogin(String refreshToken) { return null;}

    public HashMap<String, String> logout() { return null;}

}
