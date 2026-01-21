#pragma once

/**
 * @file MiddlewareAll.h
 * @brief 统一包含所有中间件头文件
 * 
 * 使用示例：
 * @code
 * #include <middleware/MiddlewareAll.h>
 * 
 * using namespace http::middleware;
 * 
 * // 创建中间件链
 * MiddlewareChain chain;
 * 
 * // 添加CORS中间件
 * chain.addMiddleware(std::make_shared<CorsMiddleware>(CorsConfig::defaultConfig()));
 * 
 * // 添加限流中间件
 * chain.addMiddleware(std::make_shared<RateLimitMiddleware>(RateLimitConfig::defaultConfig()));
 * 
 * // 添加Gzip压缩中间件
 * chain.addMiddleware(std::make_shared<GzipMiddleware>(GzipConfig::defaultConfig()));
 * 
 * // 添加认证中间件
 * auto authMiddleware = std::make_shared<AuthMiddleware>();
 * chain.addMiddleware(authMiddleware);
 * 
 * // 添加授权中间件
 * auto authzMiddleware = std::make_shared<AuthorizationMiddleware>();
 * authzMiddleware->requireRole("/api/admin/*", "admin");
 * chain.addMiddleware(authzMiddleware);
 * 
 * // 初始化角色管理器
 * RoleManager::getInstance().initializeDefaults();
 * @endcode
 */

// 基础中间件
#include "Middleware.h"
#include "MiddlewareChain.h"

// CORS中间件
#include "cors/CorsConfig.h"
#include "cors/CorsMiddleware.h"

// 限流中间件
#include "ratelimit/RateLimitConfig.h"
#include "ratelimit/RateLimitMiddleware.h"

// Gzip压缩中间件
#include "gzip/GzipConfig.h"
#include "gzip/GzipMiddleware.h"

// 认证和授权中间件
#include "auth/JwtConfig.h"
#include "auth/JwtUtil.h"
#include "auth/AuthConfig.h"
#include "auth/AuthMiddleware.h"
#include "auth/RoleManager.h"
#include "auth/AuthorizationMiddleware.h"
