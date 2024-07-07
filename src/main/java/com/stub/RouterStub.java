package com.stub;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import wiremock.org.apache.commons.lang3.math.NumberUtils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static java.lang.Integer.MAX_VALUE;
import static wiremock.org.apache.hc.core5.http.ContentType.APPLICATION_JSON;
import static wiremock.org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static wiremock.org.apache.hc.core5.http.HttpStatus.SC_OK;

@Slf4j
@SpringBootApplication
public class RouterStub implements CommandLineRunner {
    private static final RSAPublicKey RSA_PUBLIC_KEY;
    static final String KEY_ID = "router";

    @Value("${http.port:8091}")
    private int httpPort;
    @Value("${testdata.location:testdata}")
    private String testdataLocation;
    @Value("${jetty.container-threads:10}")
    private int containerThreads;
    @Value("${jetty.acceptors:2}")
    private int acceptors;
    @Value("10")
    private String acceptQueueSize;
    @Value("${jetty.header-buffer-size:8192}")
    private int headerBufferSize;

    static {
        try {
            final var keyBytes = Base64.getDecoder().decode(IOUtils.resourceToByteArray("/test_public_rsa_key"));
            final var spec = new X509EncodedKeySpec(keyBytes);
            final var kf = KeyFactory.getInstance("RSA");
            RSA_PUBLIC_KEY = (RSAPublicKey) kf.generatePublic(spec);
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static void main(final String[] args) {
        SpringApplication.run(RouterStub.class, args); // NOSONAR
    }

    @Override
    public void run(final String... args) {
        final var wireMockServer = new WireMockServer(options()
                .disableRequestJournal()
                .port(httpPort)
                .extensions(new ToHeaderTransformer(),new AdfsToHeaderTransformer())
                .usingFilesUnderClasspath(testdataLocation)
                .enableBrowserProxying(true)
               // .containerThreads(containerThreads)
               // .jettyAcceptors(acceptors)
               // .jettyAcceptQueueSize(NumberUtils.toInt(acceptQueueSize, MAX_VALUE))
               // .jettyHeaderRequestSize(headerBufferSize)
        );

        stubJwkUrl(wireMockServer);
        wireMockServer.start();
    }

    private static void stubJwkUrl(final WireMockServer wireMockServer) {
        final var jwk = new RSAKey.Builder(RSA_PUBLIC_KEY).keyID(KEY_ID).build();
        final var jwkSet = new JWKSet(jwk);
        wireMockServer.stubFor(get("/jwk")
                .atPriority(1)
                .willReturn(aResponse()
                        .withHeader(CONTENT_TYPE, APPLICATION_JSON.getMimeType())
                        .withStatus(SC_OK)
                        .withBody(jwkSet.toString())));
    }

}
