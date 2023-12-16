package app.elizon.authhelper;

import app.elizon.authhelper.process.AuthProcess;
import app.elizon.authhelper.process.impl.MinecraftMSLiveAuthProcess;

import java.io.IOException;

public class AuthHelper {

    public static void main(String[] args) {
        AuthProcess process = new AuthProcess();

        System.out.println(
                process.startAuthProcess(new MinecraftMSLiveAuthProcess())
        );

        System.out.println(
                process.reAuth(new MinecraftMSLiveAuthProcess(), "your_refresh_token")
        );
    }

}
