package app.elizon.authhelper.process;

import app.elizon.authhelper.process.impl.ProcessDetails;

import java.util.HashMap;

public class AuthProcess {

    public HashMap<String, String> startAuthProcess(ProcessDetails process) {
        return process.login();
    }

    public HashMap<String, String> reAuth(ProcessDetails process, String refreshToken) {
        return process.relogin(refreshToken);
    }

    public void logout(ProcessDetails process) {
        process.logout();
    }

}
