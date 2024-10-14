package com.templateproject.domain.auth.controller;

import com.templateproject.common.dto.ResponseDto;
import com.templateproject.domain.auth.dto.AuthRequest;
import com.templateproject.domain.auth.dto.AuthResponse;
import com.templateproject.domain.auth.dto.AuthResponse.Login;
import com.templateproject.domain.auth.service.AuthService;
import com.templateproject.security.AuthUser;
import com.templateproject.security.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth/signup")
    public ResponseEntity<ResponseDto<AuthResponse.Signup>> signup(@Valid @RequestBody AuthRequest.Signup authRequest) {
        return ResponseDto.toEntity(authService.signup(authRequest));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<ResponseDto<Login>> login(@Valid @RequestBody AuthRequest.Login authRequest) {
        return authService.login(authRequest)
            .toEntity();
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<ResponseDto<Void>> logout(@AuthenticationPrincipal AuthUser user) {
        return authService.logout(user)
            .toEntity();
    }

    @PostMapping("/auth/reissue")
    public ResponseEntity<?> reissue(@RequestHeader(JwtUtil.REFRESH_TOKEN_HEADER) String refreshToken) {
        return authService.reissue(refreshToken)
            .toEntity();
    }

    @GetMapping("/auth/nickname/check")
    public ResponseEntity<ResponseDto<AuthResponse.DuplicateCheck>> checkNickname(@RequestBody AuthRequest.CheckNickname request) {
        return authService.checkNickname(request)
            .toEntity();
    }
    @GetMapping("/auth/email/check")
    public ResponseEntity<ResponseDto<AuthResponse.DuplicateCheck>> checkEmail(@RequestBody AuthRequest.CheckEmail request) {
        return authService.checkEmail(request)
            .toEntity();
    }
    @GetMapping("/auth/username/check")
    public ResponseEntity<ResponseDto<AuthResponse.DuplicateCheck>> checkUsername(@RequestBody AuthRequest.CheckUsername request) {
        return authService.checkUsername(request)
            .toEntity();
    }

}
