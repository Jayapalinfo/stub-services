package com.stub;

import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder.ProxyResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.common.Errors;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformer;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.stub.RouterStub.KEY_ID;


@Slf4j
abstract class EmployeeCookieTransformer extends ResponseDefinitionTransformer {

    private static final RSAPrivateKey RSA_PRIVATE_KEY;
    private static final String X_AUTH_EMPLOYEE = "x-auth-employee";

    public static final String EMPLOYEE_COOKIE = "x-employee";
    public static final int EXPIRATION_TIME_SIGNATURE = 120;

    static {
        try {
            final var keyBytes = Base64.getDecoder().decode(IOUtils.resourceToByteArray("/test_private_rsa_key"));
            final var spec = new PKCS8EncodedKeySpec(keyBytes);
            final var kf = KeyFactory.getInstance("RSA");
            RSA_PRIVATE_KEY = (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public ResponseDefinition badRequest(){
        return ResponseDefinition.badRequest(
                Errors.single(1, "Missing required: " + EMPLOYEE_COOKIE + ". Not found as cookie or as header " +
                        "param."));
    }

    public ResponseDefinition getSignedJWT(JWTClaimsSet.Builder claimsSetBuilder, ResponseDefinition responseDefinition){

        var claimsSet = claimsSetBuilder.issuer("urn:federation:ri-adfs").build();
        final var signedJWT = new SignedJWT(new JWSHeader.Builder(RS256).keyID(KEY_ID).build(), claimsSet);
        final var signer = new RSASSASigner(RSA_PRIVATE_KEY);

        try {
            signedJWT.sign(signer);
        } catch (final JOSEException e) {
            throw new IllegalArgumentException(e);
        }

        final var signedHeader = signedJWT.serialize();
        log.debug("Signed header: {}", signedHeader);

        final var proxyResponseDefinitionBuilder =
                new ProxyResponseDefinitionBuilder(ResponseDefinitionBuilder.like(responseDefinition));

        return proxyResponseDefinitionBuilder
                .withAdditionalRequestHeader("Connection", "Close")
                .withAdditionalRequestHeader(X_AUTH_EMPLOYEE, signedHeader).build();

    }

    public void addRwaFunctions(String[] functions, JWTClaimsSet.Builder claimsSetBuilder){
        if (functions.length > 1) {
            claimsSetBuilder.claim("functions", functions);
        } else {
            claimsSetBuilder.claim("functions", functions.length == 0 ? "" : functions);
        }
    }

    public void addAdRoles(String[] adRoles,JWTClaimsSet.Builder claimsSetBuilder){
        if (adRoles.length > 1) {
            claimsSetBuilder.claim("role", adRoles);
        } else {
            claimsSetBuilder.claim("role", adRoles.length == 0 ? "" : adRoles);
        }
    }

}
