
package com.khaoula.secservice.sec;

import com.khaoula.secservice.sec.entities.AppUser;
import com.khaoula.secservice.sec.filters.JwtAuthenticationFilter;
import com.khaoula.secservice.sec.filters.JwtAuthorizationFilter;
import com.khaoula.secservice.sec.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;


@Configuration
@EnableWebSecurity
@Service
public class SecurityConfig{

    @Autowired
    private AuthenticationManagerBuilder authManagerBuilder;

    @Autowired
    private AccountService accountService;


   /* public SecurityConfig(AuthenticationManagerBuilder authManagerBuilder, AccountService accountService) {
        this.authManagerBuilder = authManagerBuilder;
        this.accountService = accountService;
    }*/

@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean//step 7
    public InMemoryUserDetailsManager userDetailsService(){
        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
        inMemoryUserDetailsManager = new InMemoryUserDetailsManager() {

            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = accountService.loadUserByUsername(username);
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getAppRoles().forEach(r -> {
                    authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
                });
                return new User(appUser.getUsername(), appUser.getPassword(), authorities);

            }
        };
        return inMemoryUserDetailsManager;
    }


@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    http.csrf(csrf -> csrf.disable());// step 2 //commenter cette ligne avec apres step 7
    //http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());// step 1
    http.sessionManagement((session) ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));//step 8 et enlever le commentaire de csrf
    //http.authorizeHttpRequests((auth) -> auth.requestMatchers(antMatcher("/h2-console/**")).permitAll());
    http.authorizeHttpRequests((auth) ->
            auth.requestMatchers("/h2-console/**","/refreshToken/**","/login/**").permitAll());//step 9 attention a l'ordre

    http.authorizeHttpRequests((auth) ->
            auth.requestMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN"));

    http.authorizeHttpRequests((auth) ->
            auth.requestMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER"));

//    http.authorizeHttpRequests((auth) ->
//            auth.requestMatchers(HttpMethod.GET,"/profile/**").hasAuthority("ADMIN"));

    http.authorizeHttpRequests((auth) ->
            auth.anyRequest().authenticated());//step 5
    //http.formLogin(withDefaults());//step 6 il faut en suite configurer de quel user on parle
    //formLogin doit encore etre en commentaire avec step 8
    http.headers(headers ->
            headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable()));// step 3

    http.addFilter(new JwtAuthenticationFilter(authManagerBuilder.getOrBuild()));//step 12 et step 13 sur jwtAuth file
    http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);//step 17
    return http.build();
}


//step 10 creer le package filters avec la classe JWTAuthenticationFilter


//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
//            throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }


/*@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig ) throws Exception {
        return authConfig.getAuthenticationManager();
    }*/


}

//http.authorizeHttpRequests((auth) -> auth.requestMatchers("/h2-console/**").permitAll());
//    http.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated());

// http.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated());
//http.authorizeHttpRequests((auth) -> auth.requestMatchers("/h2-console/**").permitAll());
