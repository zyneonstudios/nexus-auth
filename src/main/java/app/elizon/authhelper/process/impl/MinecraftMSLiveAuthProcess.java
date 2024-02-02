package app.elizon.authhelper.process.impl;

import app.elizon.authhelper.window.WindowHelper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class MinecraftMSLiveAuthProcess extends ProcessDetails {

    public final static String client_id = "055da844-b0ca-4643-b596-2e9b59987b39";
    public static final String MICROSOFT_AUTH_URL = "https://login.live.com/oauth20_authorize.srf" +
            "?client_id="+client_id +
            "&response_type=code" +
            "&scope=XboxLive.signin%20XboxLive.offline_access" +
            "&redirect_uri=http%3A%2F%2Flocalhost%3A" + "48521" +
            "&prompt=select_account";
    private final static Integer local_port = 48521;

    private final static Integer loginTimeoutInSeconds = 300;

    @Override
    @SuppressWarnings("all")
    public HashMap<String, String> login() {
        ServerHelper helper = new ServerHelper();

        new Thread(() -> {
            try {
                helper.startServer(local_port);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).start();

        //wait for answer

        for(int i = loginTimeoutInSeconds; i > 0 && ServerHelper.data.isEmpty(); i--) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        helper.stopServer();

        return startlogin(ServerHelper.data.get("access"), ServerHelper.data.get("refresh"));
    }

    public HashMap<String, String> startlogin(String accessToken, String refreshToken) {

        try {

            //get xbl token

            String XboxLiveToken;

            HttpURLConnection conn = (HttpURLConnection) new URI("https://user.auth.xboxlive.com/user/authenticate").toURL().openConnection();
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

            String UHS;
            String XSTS;

            conn = (HttpURLConnection) new URI("https://xsts.auth.xboxlive.com/xsts/authorize").toURL().openConnection();
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

            String minecraft_token;

            conn = (HttpURLConnection) new URI("https://api.minecraftservices.com/authentication/login_with_xbox").toURL().openConnection();
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

            String uuid;
            String name;

            conn = (HttpURLConnection) new URI("https://api.minecraftservices.com/minecraft/profile").toURL().openConnection();
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
            data.put("ms_refresh_token", refreshToken);
            data.put("minecraft_token", minecraft_token);
            data.put("uuid", uuid);
            data.put("username", name);


            return data;
        } catch (IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public HashMap<String, String> relogin(String refreshToken) {
        try {

            String accessToken;

            ServerHelper helper = new ServerHelper();
            helper.startServerHeadless(local_port);

            HttpURLConnection conn = (HttpURLConnection) new URI("https://login.live.com/oauth20_token.srf").toURL().openConnection();
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

            String XboxLiveToken;

            conn = (HttpURLConnection) new URI("https://user.auth.xboxlive.com/user/authenticate").toURL().openConnection();
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

            String UHS;
            String XSTS;

            conn = (HttpURLConnection) new URI("https://xsts.auth.xboxlive.com/xsts/authorize").toURL().openConnection();
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

            String minecraft_token;

            conn = (HttpURLConnection) new URI("https://api.minecraftservices.com/authentication/login_with_xbox").toURL().openConnection();
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

            String uuid;
            String name;

            conn = (HttpURLConnection) new URI("https://api.minecraftservices.com/minecraft/profile").toURL().openConnection();
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
            data.put("ms_refresh_token", refreshToken);
            data.put("minecraft_token", minecraft_token);
            data.put("uuid", uuid);
            data.put("username", name);

            return data;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static class ServerHelper {

        public static final HashMap<String, String> data = new HashMap<>();

        private static Map<String, String> generateCodeChallengeAndVerifier() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] codeVerifierBytes = new byte[32];
            secureRandom.nextBytes(codeVerifierBytes);
            String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);

            MessageDigest md;
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            byte[] codeChallengeBytes = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeChallengeBytes);

            Map<String, String> result = new HashMap<>();
            result.put("code_challenge", codeChallenge);
            result.put("code_verifier", codeVerifier);

            return result;
        }

        private static String verifier;
        private HttpServer server;

        @SuppressWarnings("unused")
        public void startServer(int port) throws IOException {
            server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

            server.createContext("/", new WebHandler());

            server.start();


            Map<String, String> codes = generateCodeChallengeAndVerifier();
            verifier = codes.get("code_verifier");

            new WindowHelper().openWindow(MinecraftMSLiveAuthProcess.MICROSOFT_AUTH_URL+"&code_challenge=" + codes.get("code_challenge") + "&code_challenge_method=S256");
        }

        public void stopServer() {
            server.stop(5);
        }

        static class WebHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) {
                AtomicReference<String> ret = new AtomicReference<>(null);

                try {
                    ret.set(exchange.getRequestURI().getQuery());

                    ret.get();
                    if (!ret.get().startsWith("code=")) {
                        throw new IllegalStateException("Invalid query: " + ret.get());
                    }

                    try {
                        byte[] bytes = "<p>Authentication process started. You can now close this page.</p>".getBytes();
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                        exchange.getResponseBody().flush();
                    } catch (Exception ignored) {}

                    ret.set(ret.get().replace("code=", ""));

                    String accessToken;
                    String refreshToken;


                    HttpURLConnection conn = (HttpURLConnection) new URI("https://login.live.com/oauth20_token.srf").toURL().openConnection();
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    conn.setRequestMethod("POST");
                    conn.setConnectTimeout(15000);
                    conn.setReadTimeout(15000);
                    conn.setDoOutput(true);

                    Map<String, String> codeChallengeAndVerifier = generateCodeChallengeAndVerifier();

                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(("client_id=" + URLEncoder.encode(client_id, "UTF-8") + "&" +
                                "code=" + URLEncoder.encode(ret.get(), "UTF-8") + "&" +
                                "grant_type=authorization_code&" +
                                "redirect_uri=" + URLEncoder.encode("http://localhost:48521", "UTF-8") + "&" +
                                "scope=XboxLive.signin%20XboxLive.offline_access" +
                                "&code_verifier=" + URLEncoder.encode(verifier, "UTF-8") +
                                "&code_challenge=" + URLEncoder.encode(codeChallengeAndVerifier.get("code_challenge"), "UTF-8") +
                                "&code_challenge_method=S256").getBytes(StandardCharsets.UTF_8));

                        if (conn.getResponseCode() < 200 || conn.getResponseCode() > 299) {
                            try (BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                                throw new IllegalArgumentException("codeToToken response: " + conn.getResponseCode() + ", data: " + err.lines().collect(Collectors.joining("\n")));
                            } catch (Throwable t) {
                                throw new IllegalArgumentException("codeToToken response: " + conn.getResponseCode(), t);
                            }
                        }


                        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                            JSONObject object = new JSONObject(in.lines().collect(Collectors.joining("\n")));

                            accessToken = object.getString("access_token");
                            refreshToken = object.getString("refresh_token");

                        }
                    }

                    data.put("access", accessToken);
                    data.put("refresh", refreshToken);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        public void startServerHeadless(int port) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

            AtomicReference<String> ret = new AtomicReference<>(null);

            server.createContext("/", exchange -> {

                ret.set(exchange.getRequestURI().getQuery());

                try {
                    exchange.getRequestHeaders().add("Content-Type", "text/html; charset=UTF-8");






                    byte[] bytes = "<p>Authentication process started. You can now close this page.</p>".getBytes();








                    exchange.sendResponseHeaders(200, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                        os.flush();
                    }
                } catch (Exception ex) {
                    server.stop(0);
                } finally {
                    server.stop(0);
                }
            });

        }

    }

}
