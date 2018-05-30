package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MyController {

    @RequestMapping("/user")
    public String getUser(){
        return "my user controller";
    }

    @RequestMapping("/admin")
    public String getAdmin(){
        return "my admin controller";
    }
}
