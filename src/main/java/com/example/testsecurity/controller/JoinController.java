package com.example.testsecurity.controller;

import com.example.testsecurity.dto.JoinDTO;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class JoinController {

    @GetMapping("/join")
    public String joinP(){

        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(JoinDTO joinDTO){

        System.out.println(joinDTO.getUsername());



        return "redirect:/login";
    }
}
