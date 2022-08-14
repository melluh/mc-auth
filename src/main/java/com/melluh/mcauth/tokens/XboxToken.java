package com.melluh.mcauth.tokens;

public class XboxToken extends Token {

    private final String userHash;

    public XboxToken(String value, long expiryTime, String userHash) {
        super(value, expiryTime);
        this.userHash = userHash;
    }

    public String getUserHash() {
        return userHash;
    }

}
