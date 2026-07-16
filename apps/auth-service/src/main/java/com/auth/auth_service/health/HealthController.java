package com.auth.auth_service.health;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.auth_service.common.ApiResponse;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

	@GetMapping("/health")
	public ApiResponse<Void> health() {
		return ApiResponse.success("Auth Service is up and running!");
	}

	@GetMapping("/health/readiness")
	public ApiResponse<Void> readiness() {
		return ApiResponse.success("Auth Service is ready to accept requests!");
	}

	@GetMapping("/health/liveness")
	public ApiResponse<Void> liveness() {
		return ApiResponse.success("Auth Service is alive!");
	}
}
