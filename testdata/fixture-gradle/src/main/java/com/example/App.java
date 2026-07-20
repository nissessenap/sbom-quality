package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;

import java.util.List;

/** Minimal app touching every direct dependency so none is stripped as unused. */
public final class App {
    public static void main(String[] args) throws Exception {
        List<String> parts = ImmutableList.of("sbom", "quality", "fixture");
        String joined = StringUtils.join(parts, "-");
        String json = new ObjectMapper().writeValueAsString(parts);
        System.out.println(joined + " " + json);
    }
}
