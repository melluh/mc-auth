package com.melluh.mcauth;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.melluh.mcauth.tokens.MicrosoftToken;
import com.melluh.mcauth.utils.FormBody;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public class MicrosoftAuthenticator {

    private static final URI DEVICE_CODE_URI = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode");
    private static final URI TOKEN_URI = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");

    private final HttpClient httpClient;
    private final String clientId, scope, grantType;

    private MicrosoftAuthenticator(HttpClient httpClient, String clientId, String scope, String grantType) {
        this.httpClient = httpClient;
        this.clientId = clientId;
        this.scope = scope;
        this.grantType = grantType;
    }

    private AuthenticationException getError(JsonObject json) {
        String description = json.getString("error") + " (" + json.getString("error_description").split("\\n")[0].trim() + ")";
        return new AuthenticationException("Request returned error response: " + description);
    }

    public CompletableFuture<DeviceCode> getDeviceCode() {
        return CompletableFuture.supplyAsync(() -> {
            FormBody formBody = new FormBody()
                    .add("client_id", clientId)
                    .add("scope", scope);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(DEVICE_CODE_URI)
                    .POST(formBody.asPublisher())
                    .build();

            try {
                HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                JsonObject json = JsonParser.object().from(response.body());

                if(json.has("error")) {
                    throw getError(json);
                }

                long expiryTime = System.currentTimeMillis() + json.getInt("expires_in") * 1000L;
                return new DeviceCode(json.getString("user_code"), json.getString("device_code"),
                        json.getString("verification_uri"), expiryTime, json.getInt("interval"));
            } catch (IOException | InterruptedException | JsonParserException ex) {
                throw new AuthenticationException("Device code request failed", ex);
            }
        });
    }

    public record DeviceCode(String userCode, String deviceCode, String verificationUri, long expiryTime, int checkInterval) {
        public boolean expired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    public CompletableFuture<PollingResult> pollDeviceCode(DeviceCode deviceCode) {
        if(deviceCode.expired())
            return CompletableFuture.completedFuture(new PollingResult(PollingState.EXPIRED, null));

        return CompletableFuture.supplyAsync(() -> {
            FormBody body = new FormBody()
                    .add("client_id", clientId)
                    .add("grant_type", grantType)
                    .add("device_code", deviceCode.deviceCode());

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(TOKEN_URI)
                    .POST(body.asPublisher())
                    .build();

            try {
                HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                JsonObject json = JsonParser.object().from(response.body());

                if(json.has("error")) {
                    String error = json.getString("error");
                    if(error.equals("authorization_pending"))
                        return new PollingResult(PollingState.PENDING, null);
                    if(error.equals("authorization_declined"))
                        return new PollingResult(PollingState.DECLINED, null);
                    throw getError(json);
                }

                return new PollingResult(PollingState.ACCEPTED, tokenFromJson(json));
            } catch (IOException | InterruptedException | JsonParserException ex) {
                throw new AuthenticationException("Device code polling request failed", ex);
            }
        });
    }

    public record PollingResult(PollingState state, MicrosoftToken token) {}

    public enum PollingState {
        PENDING, ACCEPTED, DECLINED, EXPIRED
    }

    public CompletableFuture<MicrosoftToken> refresh(MicrosoftToken microsoftToken) {
        return CompletableFuture.supplyAsync(() -> {
            FormBody body = new FormBody()
                    .add("client_id", clientId)
                    .add("grant_type", "refresh_token")
                    .add("scope", scope)
                    .add("refresh_token", microsoftToken.refreshToken());

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(TOKEN_URI)
                    .POST(body.asPublisher())
                    .build();

            try {
                HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                JsonObject json = JsonParser.object().from(response.body());

                if(json.has("error")) {
                    throw getError(json);
                }

                return tokenFromJson(json);
            } catch (IOException | InterruptedException | JsonParserException ex) {
                throw new AuthenticationException("Failed to send refresh request to Microsoft", ex);
            }
        });
    }

    private static MicrosoftToken tokenFromJson(JsonObject json) {
        long expiryTime = System.currentTimeMillis() + json.getInt("expires_in") * 1000L;
        return new MicrosoftToken(json.getString("access_token"), expiryTime, json.getString("refresh_token"));
    }

    public static MicrosoftAuthenticator createDefault(String clientId) {
        return createBuilder(clientId).build();
    }

    public static Builder createBuilder(String clientId) {
        return new Builder(clientId);
    }

    public static class Builder {

        private static final String DEFAULT_SCOPE = "XboxLive.signin offline_access";
        private static final String DEFAULT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

        private final String clientId;
        private HttpClient httpClient;
        private String scope = DEFAULT_SCOPE;
        private String grantType = DEFAULT_GRANT_TYPE;

        private Builder(String clientId) {
            this.clientId = Objects.requireNonNull(clientId, "clientId cannot be null");
        }

        public Builder setHttpClient(HttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient cannot be null");
            return this;
        }

        public Builder setScope(String scope) {
            this.scope = Objects.requireNonNull(scope, "scope cannot be null");
            return this;
        }

        public Builder setGrantType(String grantType) {
            this.grantType = Objects.requireNonNull(grantType, "grantType cannot be null");
            return this;
        }

        public MicrosoftAuthenticator build() {
            if(httpClient == null)
                this.httpClient = HttpClient.newHttpClient();
            return new MicrosoftAuthenticator(httpClient, clientId, scope, grantType);
        }

    }


}
