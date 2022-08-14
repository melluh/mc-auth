package com.melluh.mcauth;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;
import com.melluh.mcauth.tokens.MicrosoftToken;
import com.melluh.mcauth.tokens.XboxToken;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Instant;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public class XboxAuthenticator {

    private static final URI XBL_TOKEN_URI = URI.create("https://user.auth.xboxlive.com/user/authenticate");
    private static final URI XSTS_TOKEN_URI = URI.create("https://xsts.auth.xboxlive.com/xsts/authorize");

    private final HttpClient httpClient;

    private XboxAuthenticator(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public CompletableFuture<XboxToken> getXblToken(MicrosoftToken microsoftToken) {
        return CompletableFuture.supplyAsync(() -> {
            JsonObject properties = JsonObject.builder()
                    .value("AuthMethod", "RPS")
                    .value("SiteName", "user.auth.xboxlive.com")
                    .value("RpsTicket", "d=" + microsoftToken.getValue())
                    .done();
            return handleTokenRequest(XBL_TOKEN_URI, properties, "http://auth.xboxlive.com"); // Must be HTTP to work
        });
    }

    public CompletableFuture<XboxToken> getXstsToken(XboxToken xblToken) {
        return CompletableFuture.supplyAsync(() -> {
            JsonObject properties = JsonObject.builder()
                    .value("SandboxId", "RETAIL")
                    .array("UserTokens", Collections.singleton(xblToken.getValue()))
                    .done();
            return handleTokenRequest(XSTS_TOKEN_URI, properties, "rp://api.minecraftservices.com/");
        });
    }

    private XboxToken handleTokenRequest(URI uri, JsonObject properties, String relyingParty) {
        JsonObject reqJson = JsonObject.builder()
                .value("Properties", properties)
                .value("RelyingParty", relyingParty)
                .value("TokenType", "JWT")
                .done();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(JsonWriter.string(reqJson)))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            JsonObject json = JsonParser.object().from(response.body());

            if(json.has("XErr")) {
                long code = json.getLong("XErr");
                throw new AuthenticationException("Authentication request to Xbox Live returned error: " + code + " (" + errorDescription(code) + ")");
            }

            String token = json.getString("Token");
            long expiryTime = Instant.parse(json.getString("NotAfter")).toEpochMilli();
            String userHash = json.getObject("DisplayClaims").getArray("xui").getObject(0).getString("uhs");

            return new XboxToken(token, expiryTime, userHash);
        } catch (IOException | InterruptedException | JsonParserException ex) {
            throw new AuthenticationException("Authentication request to Xbox Live failed", ex);
        }
    }

    private static String errorDescription(long code) {
        if(code == 2148916233L)
            return "No Xbox profile associated with account";
        if(code == 2148916235L)
            return "Not available in country";
        if(code == 2148916236L || code == 2148916237L)
            return "Adult verification required (South Korea)";
        if(code == 2148916238L)
            return "Child account must be added to a family";
        return "Unknown error";
    }

    public static XboxAuthenticator createDefault() {
        return createBuilder().build();
    }

    public static Builder createBuilder() {
        return new Builder();
    }

    public static class Builder {

        private HttpClient httpClient;

        public Builder setHttpClient(HttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient cannot be null");
            return this;
        }

        public XboxAuthenticator build() {
            if (httpClient == null)
                this.httpClient = HttpClient.newHttpClient();
            return new XboxAuthenticator(httpClient);
        }

    }

}
