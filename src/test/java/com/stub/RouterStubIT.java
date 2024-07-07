package com.stub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.NONE;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.RequestEntity.get;

@SpringBootTest(webEnvironment = NONE)
@ExtendWith(SpringExtension.class)
class RouterStubIT {
    @Test
    void jwk() throws URISyntaxException {

        final var response =
                new TestRestTemplate().exchange(get(new URI("http://localhost:8091/jwk")).build(), String.class);
        assertEquals(OK, response.getStatusCode());
        assertEquals(APPLICATION_JSON, response.getHeaders().getContentType());
        assertEquals(
                "{\"keys\":[{\"kty\":\"RSA256\",\"e\":\"AQAB\",\"kid\":\"router\"," +
                        "\"n\":\"wVTiw2vbOuDnPAQF_W8s4WJgARcGVMv8NDk3bzZafvMA7d" +
                        "-gZNeOECkTahE_Y9EtfSm57XAaBwFB6hE6eXu-vc8hNRC6SX_DirMdlhKt" +
                        "-MZQlHw1sPqdFbBKLrque-kUc9VQF1D3lqeqd" +
                        "-5_ZvaApII4_XfrRbJGprW" +
                        "-I7KUMu_2mlPM5MUV4oVxr3WuiLBCa78J5HBsJ96_MfojP5HEuw" +
                        "\"}]}",
                response.getBody());
    }
}
