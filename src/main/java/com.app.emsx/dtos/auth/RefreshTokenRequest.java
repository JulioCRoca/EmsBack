package com.app.emsx.dtos.auth;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
