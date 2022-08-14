package com.melluh.mcauth.utils;

import java.net.URLEncoder;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class FormBody {

    private final Map<String, String> values = new HashMap<>();

    public FormBody add(String key, String value) {
        values.put(key, value);
        return this;
    }

    public String asRequestString() {
        return values.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    public BodyPublisher asPublisher() {
        return BodyPublishers.ofString(this.asRequestString());
    }

}
