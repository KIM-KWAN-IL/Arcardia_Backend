package profit.login.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin
@RestController
public class TestController {

//    public String test;

    @GetMapping("/test")
    public String getString(@RequestParam String input) {
        return "Received: " + input;
    }
}
