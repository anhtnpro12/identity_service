package com.anhtrinhnam02.identity_service.controller;

import com.anhtrinhnam02.identity_service.dto.request.ApiResponse;
import com.anhtrinhnam02.identity_service.dto.request.AuthenticationRequest;
import com.anhtrinhnam02.identity_service.dto.request.IntrospectRequest;
import com.anhtrinhnam02.identity_service.dto.response.AuthenticationResponse;
import com.anhtrinhnam02.identity_service.dto.response.IntrospectResponse;
import com.anhtrinhnam02.identity_service.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;

    @PostMapping("/token")
    ApiResponse<AuthenticationResponse> logIn(@RequestBody AuthenticationRequest authenticationRequest) {
        AuthenticationResponse result = authenticationService.authenticated((authenticationRequest));

        return ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();
    }

    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> logIn(@RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        IntrospectResponse result = authenticationService.introspect(request);

        return ApiResponse.<IntrospectResponse>builder()
                .result(result)
                .build();
    }
}
