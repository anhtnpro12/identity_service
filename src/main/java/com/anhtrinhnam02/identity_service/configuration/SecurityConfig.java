package com.anhtrinhnam02.identity_service.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Các endpoint public (không cần xác thực)
    private final String[] PUBLIC_ENDPOINTS = {
            "/users",
            "/auth/token",
            "/auth/introspect"
    };

    // Secret key dùng để ký/verify JWT (được inject từ application.properties/yml)
    @Value("${jwt.signerKey}")
    private String signerKey;

    /**
     * Cấu hình Spring Security filter chain
     *
     * @param httpSecurity cấu hình bảo mật của Spring Security
     * @return SecurityFilterChain đã cấu hình
     * @throws Exception nếu có lỗi trong quá trình build filter chain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // Quy định quyền truy cập các request
        httpSecurity.authorizeHttpRequests(request ->
                request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll() // Cho phép POST đến các endpoint public mà không cần login
                        .anyRequest().authenticated() // Các request còn lại bắt buộc phải xác thực
        );

        // Cấu hình resource server sử dụng JWT
        httpSecurity.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder())) // Dùng jwtDecoder() custom
        );

        // Tắt CSRF (Cross-Site Request Forgery) do API backend thường stateless, không dùng cookie session
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        // Trả về cấu hình bảo mật đã build
        return httpSecurity.build();
    }

    /**
     * Tạo JwtDecoder để verify token JWT
     *
     * @return JwtDecoder sử dụng secret key HS512
     */
    @Bean
    JwtDecoder jwtDecoder() {
        // Tạo secret key từ signerKey (chuỗi lấy từ config)
        SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");

        // Tạo JwtDecoder sử dụng HMAC với thuật toán HS512
        return NimbusJwtDecoder
                .withSecretKey(secretKeySpec)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }
}
