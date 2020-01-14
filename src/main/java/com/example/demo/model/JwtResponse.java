package com.example.demo.model;

import java.io.Serializable;

public class JwtResponse implements Serializable {
    private  static final long seriaVersionUID = -8091879091924046844L;
    private final String jwttoken;

    public JwtResponse(String jwttoken) {
        this.jwttoken = jwttoken;
    }

    public String getJwttoken() {
        return jwttoken;
    }
}
