package app.elizon.authhelper.process.impl;

import app.elizon.authhelper.server.ServerHelper;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.stream.Collectors;

public class MinecraftMSLiveAuthProcess extends ProcessDetails {

    public static final String MICROSOFT_AUTH_URL = "https://login.live.com/oauth20_authorize.srf" +
            "?client_id=XXX" +
            "&response_type=code" +
            "&scope=XboxLive.signin%20XboxLive.offline_access" +
            "&redirect_uri=http%3A%2F%2Flocalhost%3A48521" +
            "&prompt=select_account";

    private final static String client_id = "XXX";
    private final static Integer local_port = 48521;

    @Override
    public HashMap<String, String> login(String accessToken, String refreshToken) {

        System.out.println("received");

        try {

            System.out.println("started");

            /*if(!ret.startsWith("code=")) {
                throw new IllegalStateException("query={" + query + "}");
            }


            //get refresh token

            query = query.replace("code=", "");

            String accessToken = null;
            String refreshToken = null;

            System.out.println("HERE");

            HttpURLConnection conn = (HttpURLConnection) new URL("https://login.live.com/oauth20_token.srf").openConnection();
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                out.write(("client_id=" + URLEncoder.encode(client_id, "UTF-8") + "&" +
                        "code=" + URLEncoder.encode(query, "UTF-8") + "&" +
                        "grant_type=authorization_code&" +
                        "redirect_uri=" + URLEncoder.encode("http://localhost:" + local_port, "UTF-8") + "&" +
                        "scope=XboxLive.signin%20XboxLive.offline_access").getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("codeToToken response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("codeToToken response: " + conn.getResponseCode(), t);
                    }
                }

                System.out.println("HERE");

                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                    accessToken = object.getString("access_token");
                    refreshToken = object.getString("refresh_token");

                    System.out.println("access: " + accessToken);
                    System.out.println("refresh: " + refreshToken);
                }
            }

            conn.disconnect();*/

            //get xbl token

            String XboxLiveToken = null;

            HttpURLConnection conn = (HttpURLConnection) new URL("https://user.auth.xboxlive.com/user/authenticate").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                JSONObject reqProps = new JSONObject();
                reqProps.put("AuthMethod", "RPS");
                reqProps.put("SiteName", "user.auth.xboxlive.com");
                reqProps.put("RpsTicket", "d=" + accessToken);
                req.put("Properties", reqProps);
                req.put("RelyingParty", "http://auth.xboxlive.com");
                req.put("TokenType", "JWT");
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authXBL response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authXBL response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));
                    XboxLiveToken = object.getString("Token");
                }
            }

            conn.disconnect();

            //get xsts token and userhash from xbl token

            String UHS = null;
            String XSTS = null;

            conn = (HttpURLConnection) new URL("https://xsts.auth.xboxlive.com/xsts/authorize").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                JSONObject reqProps = new JSONObject();
                JSONArray userTokens = new JSONArray();
                userTokens.put(XboxLiveToken);
                reqProps.put("UserTokens", userTokens);
                reqProps.put("SandboxId", "RETAIL");
                req.put("Properties", reqProps);
                req.put("RelyingParty", "rp://api.minecraftservices.com/");
                req.put("TokenType", "JWT");
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authXSTS response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authXSTS response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                    XSTS = object.getString("Token");
                    UHS = ((JSONObject) object.getJSONObject("DisplayClaims").getJSONArray("xui").get(0)).getString("uhs");
                }
            }

            conn.disconnect();

            //auth minecraft

            String minecraft_token = null;

            conn = (HttpURLConnection) new URL("https://api.minecraftservices.com/authentication/login_with_xbox").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                req.put("identityToken", "XBL3.0 x=" + UHS + ";" + XSTS);
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authMinecraft response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authMinecraft response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));
                    minecraft_token = object.getString("access_token");
                }
            }

            conn.disconnect();

            String uuid = null;
            String name = null;

            conn = (HttpURLConnection) new URL("https://api.minecraftservices.com/minecraft/profile").openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + minecraft_token);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                    throw new IllegalArgumentException("getProfile response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                } catch (Throwable t) {
                    throw new IllegalArgumentException("getProfile response: " + conn.getResponseCode(), t);
                }
            }
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                uuid = object.getString("id").replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5");
                name = object.getString("name");
            }

            HashMap<String, String> data = new HashMap<>();
            data.put("xbl_refresh_token", refreshToken);
            data.put("minecraft_token", minecraft_token);
            data.put("uuid", uuid);
            data.put("username", name);


            System.out.println(data);

            return data;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public HashMap<String, String> relogin(String refreshToken) {
        try {

            String accessToken;

            ServerHelper helper = new ServerHelper();
            helper.startServerHeadless(local_port);

            HttpURLConnection conn = (HttpURLConnection) new URL("https://login.live.com/oauth20_token.srf").openConnection();
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                out.write(("client_id=" + URLEncoder.encode(client_id, "UTF-8") + "&" +
                        "refresh_token=" + URLEncoder.encode(refreshToken, "UTF-8") + "&" +
                        "grant_type=refresh_token&" +
                        "redirect_uri=" + URLEncoder.encode("http://localhost:" + local_port, "UTF-8") + "&" +
                        "scope=XboxLive.signin%20XboxLive.offline_access").getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("refreshToken response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("refreshToken response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));
                    accessToken = object.getString("access_token");
                }
            }

            //get xbl token

            String XboxLiveToken = null;

            conn = (HttpURLConnection) new URL("https://user.auth.xboxlive.com/user/authenticate").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                JSONObject reqProps = new JSONObject();
                reqProps.put("AuthMethod", "RPS");
                reqProps.put("SiteName", "user.auth.xboxlive.com");
                reqProps.put("RpsTicket", "d=" + accessToken);
                req.put("Properties", reqProps);
                req.put("RelyingParty", "http://auth.xboxlive.com");
                req.put("TokenType", "JWT");
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authXBL response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authXBL response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));
                    XboxLiveToken = object.getString("Token");
                }
            }

            conn.disconnect();

            //get xsts token and userhash from xbl token

            String UHS = null;
            String XSTS = null;

            conn = (HttpURLConnection) new URL("https://xsts.auth.xboxlive.com/xsts/authorize").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                JSONObject reqProps = new JSONObject();
                JSONArray userTokens = new JSONArray();
                userTokens.put(XboxLiveToken);
                reqProps.put("UserTokens", userTokens);
                reqProps.put("SandboxId", "RETAIL");
                req.put("Properties", reqProps);
                req.put("RelyingParty", "rp://api.minecraftservices.com/");
                req.put("TokenType", "JWT");
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authXSTS response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authXSTS response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                    XSTS = object.getString("Token");
                    UHS = ((JSONObject) object.getJSONObject("DisplayClaims").getJSONArray("xui").get(0)).getString("uhs");
                }
            }

            conn.disconnect();

            //auth minecraft

            String minecraft_token = null;

            conn = (HttpURLConnection) new URL("https://api.minecraftservices.com/authentication/login_with_xbox").openConnection();
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) {
                JSONObject req = new JSONObject();
                req.put("identityToken", "XBL3.0 x=" + UHS + ";" + XSTS);
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                    try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        throw new IllegalArgumentException("authMinecraft response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                    } catch (Throwable t) {
                        throw new IllegalArgumentException("authMinecraft response: " + conn.getResponseCode(), t);
                    }
                }
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));
                    minecraft_token = object.getString("access_token");
                }
            }

            conn.disconnect();

            String uuid = null;
            String name = null;

            conn = (HttpURLConnection) new URL("https://api.minecraftservices.com/minecraft/profile").openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + minecraft_token);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                    throw new IllegalArgumentException("getProfile response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                } catch (Throwable t) {
                    throw new IllegalArgumentException("getProfile response: " + conn.getResponseCode(), t);
                }
            }
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                uuid = object.getString("id").replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5");
                name = object.getString("name");
            }

            HashMap<String, String> data = new HashMap<>();
            data.put("xbl_refresh_token", refreshToken);
            data.put("minecraft_token", minecraft_token);
            data.put("uuid", uuid);
            data.put("username", name);

            System.out.println(data);

            return data;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
