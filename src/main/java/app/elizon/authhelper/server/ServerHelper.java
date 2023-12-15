package app.elizon.authhelper.server;

import app.elizon.authhelper.process.impl.MinecraftMSLiveAuthProcess;
import app.elizon.authhelper.window.WindowHelper;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class ServerHelper {

    public void startServer(int port) throws IOException, NoSuchAlgorithmException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

        AtomicReference<String> ret = new AtomicReference<>(null);

        server.createContext("/", exchange -> {

            ret.set(exchange.getRequestURI().getQuery());
            System.out.println(ret.get());

            System.out.println("started");

            if(!ret.get().startsWith("code=")) {
                throw new IllegalStateException("query={" + ret.get() + "}");
            }


            //get refresh token

            ret.set(ret.get().replace("code=", ""));

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
                out.write(("client_id=" + URLEncoder.encode("XXX", "UTF-8") + "&" +
                        "code=" + URLEncoder.encode(ret.get(), "UTF-8") + "&" +
                        "grant_type=authorization_code&" +
                        "redirect_uri=" + URLEncoder.encode("http://localhost:48521", "UTF-8") + "&" +
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

            conn.disconnect();

            System.out.println(new MinecraftMSLiveAuthProcess().login(accessToken, refreshToken));

            server.stop(0);
            try(BufferedReader in = new BufferedReader(new InputStreamReader(Objects.requireNonNull(ServerHelper.class.getResourceAsStream("/authPage.html")), StandardCharsets.UTF_8))) {
                exchange.getRequestHeaders().add("Content-Type", "text/html; charset=UTF-8");
                byte[] bytes = in.lines().collect(Collectors.joining("\n")).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                    os.flush();
                }

            } catch (Exception ex) {
                server.stop(0);
                ex.printStackTrace();
            }

        });

        server.start();

        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifierBytes = new byte[32];
        secureRandom.nextBytes(codeVerifierBytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] codeChallengeBytes = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeChallengeBytes);

        new WindowHelper().openWindow(MinecraftMSLiveAuthProcess.MICROSOFT_AUTH_URL + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256");
    }

    public void startServerHeadless(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

        AtomicReference<String> ret = new AtomicReference<>(null);

        server.createContext("/", exchange -> {

            ret.set(exchange.getRequestURI().getQuery());

            try(BufferedReader in = new BufferedReader(new InputStreamReader(Objects.requireNonNull(ServerHelper.class.getResourceAsStream("/authPage.html")), StandardCharsets.UTF_8))) {
                exchange.getRequestHeaders().add("Content-Type", "text/html; charset=UTF-8");
                byte[] bytes = in.lines().collect(Collectors.joining("\n")).getBytes(StandardCharsets.UTF_8);
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

        System.out.println(ret.get());
    }

}
