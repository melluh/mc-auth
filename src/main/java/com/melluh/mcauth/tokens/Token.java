package com.melluh.mcauth.tokens;

public abstract class Token {

    private final String value;
    private final long expiryTime;

    public Token(String value, long expiryTime) {
        this.value = value;
        this.expiryTime = expiryTime;
    }

    public String getValue() {
        return value;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > expiryTime;
    }

}
