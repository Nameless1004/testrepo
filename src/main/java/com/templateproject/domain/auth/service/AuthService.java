package com.templateproject.domain.auth.service;

import com.templateproject.common.dto.ResponseDto;
import com.templateproject.common.enums.TokenType;
import com.templateproject.common.enums.UserRole;
import com.templateproject.common.exceptions.AuthException;
import com.templateproject.common.exceptions.InvalidRequestException;
import com.templateproject.domain.auth.dto.AuthRequest;
import com.templateproject.domain.auth.dto.AuthRequest.Login;
import com.templateproject.domain.auth.dto.AuthResponse;
import com.templateproject.domain.auth.dto.AuthResponse.DuplicateCheck;
import com.templateproject.domain.auth.dto.AuthResponse.Reissue;
import com.templateproject.domain.user.entitiy.User;
import com.templateproject.domain.user.repository.UserRepository;
import com.templateproject.security.AuthUser;
import com.templateproject.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final RedissonClient redissonClient;

    @Value("${ADMIN_TOKEN}")
    private String adminToken;

    /**
     * 회원 가입
     * @param request
     * @return
     */
    public ResponseDto<AuthResponse.Signup> signup(AuthRequest.Signup request) {
        if(!request.password().matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*(),.?\":{}|<>])[A-Za-z\\d!@#$%^&*(),.?\":{}|<>]{8,}$")) {
            throw new InvalidRequestException("비밀번호는 대소문자 포함 영문 + 숫자 + 특수문자를 최소 1글자씩 포함해야하며 최소 8글자 이상이어야 합니다.");
        }

        if(request.userRole() == UserRole.ROLE_ADMIN) {
            if( !StringUtils.hasText(request.adminToken()) || !request.adminToken().equals(adminToken)) {
                throw new AuthException("관리자 권한이 없습니다.");
            }
        }

        String username = request.username();
        String password = passwordEncoder.encode(request.password());
        String email = request.email();
        String nickname = request.nickname();

        // 회원 중복 확인
        if (userRepository.existsByUsername(username)) {
            throw new InvalidRequestException("중복된 아이디가 존재합니다.");
        }

        // email 중복확인
        if (userRepository.existsByEmail(email)) {
            throw new InvalidRequestException("중복된 Email 입니다.");
        }

        // nickname 중복확인
        if (userRepository.existsByNickname(nickname)) {
            throw new InvalidRequestException("중복된 닉네임 입니다.");
        }

        // 사용자 등록
        User user = new User(username, password, email, nickname, request.userRole());
        user = userRepository.save(user);

        return ResponseDto.of(HttpStatus.CREATED, null, new AuthResponse.Signup(user.getId()));
    }

    /**
     * 로그인
     * @param request
     * @return
     */
    public ResponseDto<AuthResponse.Login> login(Login request) {
        User user = userRepository.findByUsername(request.username()).orElseThrow(()-> new InvalidRequestException("아이디 또는 비밀번호가 잘못되었습니다."));


        if(!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new InvalidRequestException("아이디 또는 비밀번호가 잘못되었습니다.");
        }

        // 어드민 로그인 시 어드민 토큰 검증
        if(user.getRole() == UserRole.ROLE_ADMIN) {
            if(!StringUtils.hasText(request.adminToken())){
                throw new AuthException("관리자 권한이 없습니다.");
            }

            if(!request.adminToken().equals(adminToken)) {
                throw new AuthException("관리자 권한이 없습니다.");
            }
        }

        String accessToken = jwtUtil.createAccessToken(user.getId(), user.getEmail(), user.getRole());
        String refreshToken = jwtUtil.createRefreshToken(user.getId(), user.getEmail(), user.getRole());

        redissonClient.getBucket(JwtUtil.REDIS_REFRESH_TOKEN_PREFIX + user.getId()).set(refreshToken, Duration.ofMillis(TokenType.REFRESH.getLifeTime()));
        return ResponseDto.of(HttpStatus.OK, "성공적으로 로그인 되었습니다.",new AuthResponse.Login(user, accessToken, refreshToken));

    }

    /**
     * 로그 아웃
     * @param user
     * @return
     */
    public ResponseDto<Void> logout(AuthUser user) {
        redissonClient.getBucket(JwtUtil.REDIS_REFRESH_TOKEN_PREFIX + user.getUserId()).delete();
        return ResponseDto.of(HttpStatus.OK, "로그아웃되었습니다.");
    }

    /**
     * 액세스, 리프레쉬 토큰 재발행
     * @param refreshToken
     * @return
     */
    public ResponseDto<?> reissue(String refreshToken) {

        if(refreshToken == null) {
            return ResponseDto.of(HttpStatus.BAD_REQUEST, "재발급하려면 리프레쉬 토큰이 필요합니다.", null);
        }

        // 프론트에서 붙여준 Bearer prefix 제거
        try{
            refreshToken = jwtUtil.substringToken(refreshToken);
        } catch (NullPointerException e) {
            return ResponseDto.of(HttpStatus.BAD_REQUEST, "잘못된 토큰 형식 입니다.", null);
        }

        // 리프레쉬 토큰인지 검사
        String category = jwtUtil.getTokenCategory(refreshToken);
        if (!category.equals(TokenType.REFRESH.name())) {
            return ResponseDto.of(HttpStatus.BAD_REQUEST, "리프레쉬 토큰이 아닙니다.");
        }

        // 토큰 만료 검사
        try{
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            return ResponseDto.of(HttpStatus.UNAUTHORIZED, "만료된 리프레쉬 토큰입니다.", null);
        }


        String key = JwtUtil.REDIS_REFRESH_TOKEN_PREFIX  + jwtUtil.getUserId(refreshToken);
        // 레디스에서 리프레쉬 토큰을 가져온다.
        refreshToken = (String) redissonClient.getBucket(key).get();

        if (refreshToken == null) {
            return ResponseDto.of(HttpStatus.UNAUTHORIZED, "만료된 리프레쉬 토큰입니다.", null);
        }

        // redis에서 꺼내온 리프레쉬 토큰 prefix 제거
        refreshToken = jwtUtil.substringToken(refreshToken);

        // 검증이 통과되었다면 refresh 토큰으로 액세스 토큰을 발행해준다.
        Claims claims = jwtUtil.extractClaims(refreshToken);
        Long userId = Long.parseLong(claims.getSubject());
        String email = claims.get("email", String.class);
        UserRole userRole = UserRole.of(claims.get("userRole", String.class));

        // 새 토큰 발급
        String newAccessToken = jwtUtil.createAccessToken(userId, email, userRole);
        String newRefreshToken = jwtUtil.createRefreshToken(userId, email, userRole);

        // TTL 새로해서
        String userIdToString = String.valueOf(userId);
        RBucket<Object> refreshBucket = redissonClient.getBucket(JwtUtil.REDIS_REFRESH_TOKEN_PREFIX + userIdToString);
        long ttl = refreshBucket.remainTimeToLive();

        if(ttl < 0) {
            return ResponseDto.of(HttpStatus.UNAUTHORIZED, "만료된 리프레쉬 토큰입니다.", null);
        }

        refreshBucket.set(newRefreshToken, Duration.ofMillis(ttl));

        Reissue reissue = new Reissue(newAccessToken, newRefreshToken);

        return  ResponseDto.of(HttpStatus.OK, "", reissue);
    }

    /**
     * 유저 닉네임 중복 체크
     * @param request
     * @return
     */
    public ResponseDto<AuthResponse.DuplicateCheck> checkNickname(AuthRequest.CheckNickname request) {
        DuplicateCheck duplicateCheck = new DuplicateCheck(
            userRepository.existsByNickname(request.nickname()));

        return ResponseDto.of(HttpStatus.OK, duplicateCheck);
    }

    /**
     * 유저 이메일 중복 체크
     * @param request
     * @return
     */
    public ResponseDto<AuthResponse.DuplicateCheck> checkEmail(AuthRequest.CheckEmail request) {
        DuplicateCheck duplicateCheck = new DuplicateCheck(
            userRepository.existsByEmail(request.email()));

        return ResponseDto.of(HttpStatus.OK, duplicateCheck);
    }

    /**
     * 유저 아이디 중복 체크
     * @param request
     * @return
     */
    public ResponseDto<AuthResponse.DuplicateCheck> checkUsername(AuthRequest.CheckUsername request) {
        DuplicateCheck duplicateCheck = new DuplicateCheck(
            userRepository.existsByUsername(request.username()));

        return ResponseDto.of(HttpStatus.OK, duplicateCheck);
    }
}
