package com.stub;

import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;

import java.net.URLDecoder;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
class ToHeaderTransformer extends EmployeeCookieTransformer {

    private static final String NAME = "employee-cookie";

    @Override
    public boolean applyGlobally() {
        return false;
    }

    @Override
    public ResponseDefinition transform(final Request request, final ResponseDefinition responseDefinition,
                                        final FileSource files, final Parameters parameters) {
        final var authTicketCookie = request.getCookies().get(EMPLOYEE_COOKIE);

        log.debug("Cookie {}: [{}]", EMPLOYEE_COOKIE, authTicketCookie);

        if (authTicketCookie == null) {
            return badRequest();
        }
        var decodedCookieValue = URLDecoder.decode(authTicketCookie.getValue(), UTF_8);

        EmployeeDetails parsedDtls = EmployeeDetails.parse(decodedCookieValue.split(";")[0]);

        final var claimsSetBuilder = new JWTClaimsSet.Builder().issueTime(new Date())
                .expirationTime(Date.from(ZonedDateTime.now().plusSeconds(EXPIRATION_TIME_SIGNATURE).toInstant()))
                .issueTime(Date.from(Instant.now()))
                .claim("appid", "Router Advice-Planner")
                .claim("apptype", "Confidential")
                .claim("aud", "microsoft:identityserver:Router Advice-Planner")
                .claim("auth_time", Instant.now().toString())
                .claim("authmethod", "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows")
                .claim("iss", "urn:federation:ri-adfs")
                .claim("scp", "openid")
                .claim("ver", "1.0");

        addRwaFunctions(parsedDtls.getRwaFunctions(), claimsSetBuilder);
        return getSignedJWT(claimsSetBuilder, responseDefinition);
    }

    @Override
    public String getName() {
        return NAME;
    }

}
