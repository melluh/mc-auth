package com.melluh.mcauth.utils;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.UUID;

public class AuthUtils {

    private AuthUtils() {}

    public static UUID parseMojangUuid(String uuid) {
        if(uuid.length() != 32)
            throw new IllegalStateException("Unexpected length: " + uuid.length() + " (should be 34)");

        return UUID.fromString(uuid.substring(0, 8) + "-" + uuid.substring(8, 12) + "-" + uuid.substring(12, 16) + "-" +
                uuid.substring(16, 20) + "-" + uuid.substring(20, 32));
    }

    public static String minifyUuid(UUID uuid) {
        return uuid.toString().replace("-", "");
    }

    public static String calculateServerHash(String serverId, PublicKey publicKey, SecretKey secretKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(serverId.getBytes(StandardCharsets.ISO_8859_1));
            digest.update(secretKey.getEncoded());
            digest.update(publicKey.getEncoded());
            return new BigInteger(digest.digest()).toString(16);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-1 hashing algorithm not available", ex);
        }
    }

}
