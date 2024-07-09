package com.covestro.utill;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.IOException;
import java.io.Writer;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.io.IOUtils;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

public class JWTTokenUtil {

  static final String KEY_ID = "6n2pdt0rjc1g7blaujvp5ui3o0";

  private static RSAPrivateKey getRSAPrivateKey(){
    try {
      final var keyBytes = Base64.getDecoder().decode(IOUtils.resourceToByteArray("/test_private_rsa_key"));
      final var spec = new PKCS8EncodedKeySpec(keyBytes);
      final var kf = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) kf.generatePrivate(spec);
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException| IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static String generateSignedJWTToken()  {
    ZonedDateTime zonedDateTime = ZonedDateTime.now();
    Date now = Date.from(zonedDateTime.toInstant());
    Date exp = Date.from(zonedDateTime.plusYears(100).toInstant());
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .expirationTime(exp)
        .issueTime(now)
        .issuer("https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_5Thd3nZpe")
        .claim("auth_time", now)
        .claim("custom:cwid","CVSTN")
        .claim("given_name","Jayapal")
        .claim("client_id","6n2pdt0rjc1g7blaujvp5ui3o0")
        .claim("token_use","access")
        .claim("family_name","Karyppanadar")
        .claim("email","jayapal.karuppanadar@covestro.com")
        .claim("scope","openid profile email")
        .claim("custom:companyCode","1968")
        .claim("username","jayapal.karuppanadar@covestro.com")
        .claim("version", 2)
        .build();

    final var signedJWT = new SignedJWT(new JWSHeader.Builder(RS256)
        .keyID(KEY_ID)
        .build(), claimsSet);
    final var signer = new RSASSASigner(getRSAPrivateKey());

    try {
      signedJWT.sign(signer);
    } catch (final JOSEException e) {
      throw new IllegalArgumentException(e);
    }

    return signedJWT.serialize();
  }

  public static void generateRRSAKeyPair() {

    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair pair = generator.generateKeyPair();
      String e = Base64.getEncoder().withoutPadding().encodeToString(pair.getPrivate().getEncoded());
      String f = Base64.getEncoder().withoutPadding().encodeToString(pair.getPublic().getEncoded());
      try (Writer out = new FileWriter("test_private_rsa_key");
           Writer out1 = new FileWriter("test_public_rsa_key")) {
        out.write(e);
        out1.write(f);
      }
    } catch (NoSuchAlgorithmException | IOException e) {
    throw new RuntimeException(e);
  }
  }

}


