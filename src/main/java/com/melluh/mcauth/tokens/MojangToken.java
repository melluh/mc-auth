package com.melluh.mcauth.tokens;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.melluh.mcauth.AuthenticationException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class MojangToken extends Token {

    public MojangToken(String value, long expiryTime) {
        super(value, expiryTime);
    }

    // xuid = Xbox User ID
    public String getXboxUserId() {
        try {
            JsonObject json = this.jwtPayload();
            return json.getString("xuid");
        } catch (JsonParserException ex) {
            throw new AuthenticationException("Failed to get XUID from Mojang JWT - invalid JSON", ex);
        }
    }

    // This does not verify the signature
    private JsonObject jwtPayload() throws JsonParserException {
        String[] jwtParts = this.getValue().split("\\.");
        if(jwtParts.length != 3)
            throw new IllegalStateException("Failed to get XUID from Mojang JWT, invalid token format");

        String payloadStr = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
        return JsonParser.object().from(payloadStr);
    }

}
