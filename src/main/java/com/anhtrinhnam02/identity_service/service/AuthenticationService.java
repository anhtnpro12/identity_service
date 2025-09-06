package com.anhtrinhnam02.identity_service.service;

import com.anhtrinhnam02.identity_service.dto.request.AuthenticationRequest;
import com.anhtrinhnam02.identity_service.dto.request.IntrospectRequest;
import com.anhtrinhnam02.identity_service.dto.response.AuthenticationResponse;
import com.anhtrinhnam02.identity_service.dto.response.IntrospectResponse;
import com.anhtrinhnam02.identity_service.entity.User;
import com.anhtrinhnam02.identity_service.exception.AppException;
import com.anhtrinhnam02.identity_service.exception.ErrorCode;
import com.anhtrinhnam02.identity_service.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;
    PasswordEncoder passwordEncoder;

    @NonFinal // Không sử dụng tiêm vào construction
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;

    /**
     * Introspect (kiểm tra) token JWT.
     * - Xác thực chữ ký của token bằng HMAC (MACVerifier).
     * - Kiểm tra thời gian hết hạn (expiration time).
     * - Trả về kết quả token có hợp lệ hay không.
     *
     * @param request đối tượng chứa token cần kiểm tra
     * @return IntrospectResponse cho biết token có hợp lệ không
     * @throws JOSEException  nếu có lỗi khi xác minh chữ ký
     * @throws ParseException nếu token không thể parse thành JWT hợp lệ
     */
    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        // Lấy token từ request
        var token = request.getToken();

        // Tạo verifier với khóa bí mật (HMAC) để xác minh chữ ký
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        // Parse chuỗi token thành đối tượng SignedJWT
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Lấy thời gian hết hạn của token từ claim
        Date expireTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        // Xác minh chữ ký của token
        var verified = signedJWT.verify(verifier);

        // Token hợp lệ nếu:
        // - Chữ ký đúng
        // - Thời gian hiện tại vẫn trước thời gian hết hạn
        return IntrospectResponse.builder()
                .valid(verified && expireTime.after(new Date()))
                .build();
    }

    public AuthenticationResponse authenticated(AuthenticationRequest authenticationRequest) {
        var user = userRepository.findByUsername(authenticationRequest.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        boolean authenticated = passwordEncoder.matches(authenticationRequest.getPassword(), user.getPassword());

        if (!authenticated) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        var token = generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

    /**
     * Sinh token JWT cho một user cụ thể.
     * - Sử dụng thuật toán HS512 để ký token.
     * - Thêm các thông tin cơ bản: subject (user), issuer, issue time, expiration time.
     * - Có thể bổ sung thêm custom claim.
     *
     * @param user tên user cần sinh token
     * @return token JWT đã được ký và serialize thành chuỗi
     */
    private String generateToken(User user) {
        // Tạo header cho JWT, chỉ định thuật toán ký là HS512
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        // Xây dựng claims (payload) cho JWT
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername()) // Chủ thể của token (user)
                .issuer("anhtrinhnam02.com") // Đơn vị phát hành token
                .issueTime(new Date()) // Thời gian phát hành
                .expirationTime(new Date(
                        // Token hết hạn sau 1 giờ kể từ hiện tại
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()
                ))
                .claim("scope", buildScope(user)) // Thêm custom claim nếu cần
                .build();

        // Gói claims thành payload
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        // Tạo đối tượng JWSObject gồm header + payload
        JWSObject jwsObject = new JWSObject(header, payload);

        // Ký token bằng khóa bí mật
        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));

            // Trả về token dưới dạng chuỗi
            return jwsObject.serialize();
        } catch (JOSEException e) {
            // Log lỗi nếu ký thất bại
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }
    }

    private String buildScope(User user) {
        return (user.getRoles() == null || user.getRoles().isEmpty())
                ? ""
                : String.join(" ", user.getRoles());
    }
}
