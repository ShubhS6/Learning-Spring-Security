package com.secure.notes.controller;

import com.secure.notes.jwt.JwtUtils;
import com.secure.notes.login.LoginRequest;
import com.secure.notes.login.LoginResponse;
import com.secure.notes.model.AppRole;
import com.secure.notes.model.Role;
import com.secure.notes.model.User;
import com.secure.notes.repository.RoleRepository;
import com.secure.notes.repository.UserRepository;
import com.secure.notes.securityService.UserDetailsImpl;
import com.secure.notes.service.TotpService;
import com.secure.notes.service.UserService;
import com.secure.notes.signup.SignupRequest;
import com.secure.notes.userinfo.MessageResponse;
import com.secure.notes.userinfo.UserInfoResponse;
import com.secure.notes.util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthUtil authUtil;
    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserService userService;

    @Autowired
    TotpService totpService;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{
            authentication= authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword())
            );
        }catch(AuthenticationException exception){
            Map<String,Object> map=new HashMap<>();
            map.put("message","Bad Credentials");
            map.put("status",false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails=(UserDetailsImpl) authentication.getPrincipal();
        String jwtToken= jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles=userDetails.getAuthorities().stream()
                .map(i->i.getAuthority()).collect(Collectors.toList());

        LoginResponse response=new LoginResponse(jwtToken,userDetails.getUsername(), roles);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){
        if(userRepository.existsByUserName(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken"));
        }

        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageResponse("Email is already taken"));
        }

        User user=new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles= signupRequest.getRole();

        Role role;

        if(strRoles==null || strRoles.isEmpty()){
            role=roleRepository.findByRoleName(AppRole.ROLE_USER).orElseThrow(()-> new RuntimeException("Error : Role is not found"));
        }else{
            String roleStr=strRoles.iterator().next();
            if(roleStr.equals("admin")){
                role=roleRepository.findByRoleName(AppRole.ROLE_ADMIN).orElseThrow(()->new RuntimeException("Error : Role is not found"));
            }else{
                role=roleRepository.findByRoleName(AppRole.ROLE_USER).orElseThrow(()->new RuntimeException("Error : Role is not found"));
            }
            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User Register Successfully"));
    }


    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails){
        User user= userService.findByUsername(userDetails.getUsername());
        List<String> roles=userDetails.getAuthorities().stream().map(i->i.getAuthority()).collect(Collectors.toList());
        UserInfoResponse response=new UserInfoResponse(
            user.getUserId(),
            user.getUserName(),
            user.getEmail(),
            user.isAccountNonLocked(),
            user.isAccountNonExpired(),
            user.isCredentialsNonExpired(),
            user.isEnabled(),
            user.getCredentialsExpiryDate(),
            user.getAccountExpiryDate(),
            user.isTwoFactorEnabled(),
            roles
        );
        return ResponseEntity.ok().body(response);
    }

    @GetMapping("/username")
    public String currentUserName(@AuthenticationPrincipal UserDetails userDetails){
        return (userDetails!=null)?userDetails.getUsername():"";
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email){
        try{
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password Reset Email sent"));
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error sending password reset email"));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token,@RequestParam String newPassword){
        try {
            userService.resetPassword(token,newPassword);
            return ResponseEntity.ok(new MessageResponse("Password Reset Successfull"));
        }catch (RuntimeException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(e.getMessage()));
        }
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA(){
        Long userId= authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret=userService.generate2FASecret(userId);
        String qrCodeUrl=totpService.getQrCodeUrl(secret,userService.getUserById(userId).getUserName());
        return ResponseEntity.ok(qrCodeUrl);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA(){
        Long userId= authUtil.loggedInUserId();
        userService.diable2FA(userId);
        return ResponseEntity.ok("2Fa desable");
    }



    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code) {
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }


    @PostMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null){
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }
    }


    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code,
                                                 @RequestParam String jwtToken) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

}
