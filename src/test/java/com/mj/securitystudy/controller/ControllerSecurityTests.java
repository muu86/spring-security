package com.mj.securitystudy.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest
public class ControllerSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithAnonymousUser
    public void myAccountNoAuth401() throws Exception {
        mockMvc.perform(get("/my-account"))
            .andExpect(status().isUnauthorized())
            .andDo(print());
    }

    @Test
    @WithMockUser
    public void myAccountWithAuth200() throws Exception {
        mockMvc.perform(get("/my-account"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    public void contactNoAuth200() throws Exception {
        mockMvc.perform(get("/contact"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    public void deny401() throws Exception {
        mockMvc.perform(get("/deny"))
            .andExpect(status().isUnauthorized());
    }
}
