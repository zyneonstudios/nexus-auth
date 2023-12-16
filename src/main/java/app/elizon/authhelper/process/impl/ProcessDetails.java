package app.elizon.authhelper.process.impl;

import java.lang.reflect.Executable;
import java.util.HashMap;

public abstract class ProcessDetails {

    @SuppressWarnings("all")
    public HashMap<String, String> login() { return null;}

    @SuppressWarnings("all")
    public HashMap<String, String> relogin(String refreshToken) { return null;}

    @SuppressWarnings("all")
    public boolean logout() { return true;}

}
