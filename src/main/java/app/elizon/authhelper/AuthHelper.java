package app.elizon.authhelper;

import app.elizon.authhelper.server.ServerHelper;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class AuthHelper {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        int local_port = 48521;

        ServerHelper helper = new ServerHelper();

        helper.startServer(local_port);

    }

}
