package com.example.obspringsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/hola").permitAll() //esta línea de metodos, se puede repetir, tantas url queramos.
                .antMatchers("/bootstrap").hasRole("ADMIN")
                .anyRequest().authenticated() /* esta línea indica que, todo tiene que estar autenticado, por lo tanto antes de esta linea se tiene que indicar lo que queremos que sea Desarrollador Java / Angular Jr.accesible sin logearnos. */
                .and()
                .formLogin()
                .and()
                .httpBasic();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}1234").roles("USER") //aqui se agrega {noop} para indicarle a spring security que la contraseña esta en texto plano, no esta codificada.
                .and()
                .withUser("admin").password(passwordEncoder().encode("password")).roles("USER", "ADMIN"); // qui el password se codifica con el bean metodo passwordEncoder().

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public HttpFirewall looseHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();

        firewall.setAllowBackSlash(true);
        firewall.setAllowSemicolon(true);
        firewall.setAllowUrlEncodedSlash(true);

        return firewall;
    }
}
