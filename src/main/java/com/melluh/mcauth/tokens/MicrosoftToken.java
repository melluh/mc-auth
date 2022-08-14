package com.melluh.mcauth.tokens;

public class MicrosoftToken extends Token {

    private final String refreshToken;

    public MicrosoftToken(String accessToken, long expiryTime, String refreshToken) {
        super(accessToken, expiryTime);
        this.refreshToken = refreshToken;
    }

    public String refreshToken() {
        return refreshToken;
    }

}
