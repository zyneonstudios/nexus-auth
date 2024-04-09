package live.nerotv.zyneon.auth;

import app.elizon.authhelper.process.AuthProcess;
import app.elizon.authhelper.process.impl.MinecraftMSLiveAuthProcess;

import java.util.HashMap;

public class ZyneonAuth {

    public static void main(String[] args) {
        getAuthInfos();
    }

    public static HashMap<AuthInfo,String> getAuthInfos() {
        //CREATING MAP
        HashMap<AuthInfo,String> map = new HashMap<>();
        try {
            //AUTHENTICATE AND RETURN DATA
            MinecraftMSLiveAuthProcess process = new MinecraftMSLiveAuthProcess();
            HashMap<String, String> authData = new AuthProcess().startAuthProcess(process);
            MinecraftMSLiveAuthProcess.ServerHelper.data = new HashMap<>();

            //ADDING DATA FROM AUTH DATA TO MAP
            map.put(AuthInfo.ACCESS_TOKEN,authData.get("minecraft_token"));
            map.put(AuthInfo.REFRESH_TOKEN,authData.get("ms_refresh_token"));
            map.put(AuthInfo.USERNAME,authData.get("username"));
            map.put(AuthInfo.UUID,authData.get("uuid"));

            process.getServer().stopServer();
            process.setServer(null);
            System.gc();
        } catch (Exception e) {
            //RETURNING NULL IF ERROR
            return null;
        }
        //RETURNING MAP
        return map;
    }

    public static HashMap<AuthInfo,String> getAuthInfos(String refreshToken) {
        //CREATING MAP
        HashMap<AuthInfo,String> map = new HashMap<>();
        try {
            //AUTHENTICATE AND RETURN DATA
            MinecraftMSLiveAuthProcess process = new MinecraftMSLiveAuthProcess();
            HashMap<String, String> authData = new AuthProcess().reAuth(process, refreshToken);
            MinecraftMSLiveAuthProcess.ServerHelper.data = new HashMap<>();

            //ADDING DATA FROM AUTH DATA TO MAP
            map.put(AuthInfo.ACCESS_TOKEN,authData.get("minecraft_token"));
            map.put(AuthInfo.REFRESH_TOKEN,authData.get("ms_refresh_token"));
            map.put(AuthInfo.USERNAME,authData.get("username"));
            map.put(AuthInfo.UUID,authData.get("uuid"));

            process.getServer().stopServer();
            process.setServer(null);
            System.gc();
        } catch (Exception e) {
            //RETURNING NULL IF ERROR
            return null;
        }
        //RETURNING MAP
        return map;
    }

    public enum AuthInfo {
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        USERNAME,
        UUID
    }
}
