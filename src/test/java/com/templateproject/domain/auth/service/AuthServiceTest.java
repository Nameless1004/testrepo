package com.templateproject.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import com.templateproject.common.dto.ResponseDto;
import com.templateproject.common.enums.UserRole;
import com.templateproject.common.exceptions.AuthException;
import com.templateproject.common.exceptions.InvalidRequestException;
import com.templateproject.domain.auth.dto.AuthRequest;
import com.templateproject.domain.auth.dto.AuthResponse.Signup;
import com.templateproject.domain.user.entitiy.User;
import com.templateproject.domain.user.repository.UserRepository;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Spy
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthService authService;

    @Nested
    class 회원가입 {
        @Test
        public void 회원가입_성공() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", null, UserRole.ROLE_USER);
            given(userRepository.existsByUsername(any())).willReturn(false);
            given(userRepository.existsByNickname(any())).willReturn(false);
            given(userRepository.existsByEmail(any())).willReturn(false);
            User user = new User("username", "AAbb1234!", "email", "nn", UserRole.ROLE_USER);
            ReflectionTestUtils.setField(user, "id", 1L);
            given(userRepository.save(any())).willReturn(user);
            // when
            ResponseDto<Signup> signup = authService.signup(authRequest);

            // then
            assertThat(signup.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());
            assertThat(signup.getData().userId()).isEqualTo(1L);
        }

        @Test
        public void 어드민_회원가입_성공() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", "1", UserRole.ROLE_USER);
            given(userRepository.existsByUsername(any())).willReturn(false);
            given(userRepository.existsByNickname(any())).willReturn(false);
            given(userRepository.existsByEmail(any())).willReturn(false);
            User user = new User("username", "AAbb1234!", "email", "nn", UserRole.ROLE_USER);
            ReflectionTestUtils.setField(user, "id", 1L);
            given(userRepository.save(any())).willReturn(user);
            ReflectionTestUtils.setField(authService, "adminToken", "1");
            // when
            ResponseDto<Signup> signup = authService.signup(authRequest);

            // then
            assertThat(signup.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());
            assertThat(signup.getData().userId()).isEqualTo(1L);
        }
        @Test
        public void 회원가입_비밀번호_조건에_부합하지않을_때() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "aab234!", "email", "nn", null, UserRole.ROLE_USER);
            // when then
            assertThatThrownBy(() -> authService.signup(authRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("비밀번호는 대소문자 포함 영문 + 숫자 + 특수문자를 최소 1글자씩 포함해야하며 최소 8글자 이상이어야 합니다.");
        }

        @Test
        public void 유저역할이_관리자인데_어드민_토큰이_없거나_다를때() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", null, UserRole.ROLE_ADMIN);
            // when then
            assertThatThrownBy(() -> authService.signup(authRequest))
                .isInstanceOf(AuthException.class)
                .hasMessage("관리자 권한이 없습니다.");

            AuthRequest.Signup authRequest2 = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn",
                "test", UserRole.ROLE_ADMIN);
            assertThatThrownBy(() -> authService.signup(authRequest2))
                .isInstanceOf(AuthException.class)
                .hasMessage("관리자 권한이 없습니다.");
        }

        @Test
        public void 중복된_유저네임이_있을_때() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", null, UserRole.ROLE_USER);
            given(userRepository.existsByUsername(any())).willReturn(true);
            // when then
            assertThatThrownBy(() -> authService.signup(authRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("중복된 아이디가 존재합니다.");
        }

        @Test
        public void 중복된_이메일이_있을_때() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", null, UserRole.ROLE_USER);
            given(userRepository.existsByUsername(any())).willReturn(false);
            given(userRepository.existsByEmail(any())).willReturn(true);
            // when then
            assertThatThrownBy(() -> authService.signup(authRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("중복된 Email 입니다.");
        }

        @Test
        public void 중복된_닉네임이_있을_때() throws Exception {
            // given
            AuthRequest.Signup authRequest = new AuthRequest.Signup("username", "AAbb1234!", "email", "nn", null, UserRole.ROLE_USER);
            given(userRepository.existsByUsername(any())).willReturn(false);
            given(userRepository.existsByEmail(any())).willReturn(false);
            given(userRepository.existsByNickname(any())).willReturn(true);
            // when then
            assertThatThrownBy(() -> authService.signup(authRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("중복된 닉네임 입니다.");
        }
    }

    @Nested
    class 로그인 {

    }

}