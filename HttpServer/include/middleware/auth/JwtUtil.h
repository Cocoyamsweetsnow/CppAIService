#pragma once

#include "JwtConfig.h"
#include <string>
#include <memory>

namespace http 
{
namespace middleware 
{

/**
 * @brief JWT工具类
 * 
 * 提供JWT的生成、验证、解析功能
 */
class JwtUtil
{
public:
    /**
     * @brief 构造函数
     * @param config JWT配置
     */
    explicit JwtUtil(const JwtConfig& config = JwtConfig::defaultConfig());
    
    /**
     * @brief 生成JWT Token
     * @param claims JWT声明
     * @return 生成的token字符串
     */
    std::string generateToken(const JwtClaims& claims);
    
    /**
     * @brief 生成Access Token
     * @param userId 用户ID
     * @param username 用户名
     * @param roles 用户角色列表
     * @param permissions 权限列表
     * @return 生成的token字符串
     */
    std::string generateAccessToken(
        const std::string& userId,
        const std::string& username,
        const std::vector<std::string>& roles = {},
        const std::vector<std::string>& permissions = {}
    );
    
    /**
     * @brief 生成Refresh Token
     * @param userId 用户ID
     * @return 生成的refresh token字符串
     */
    std::string generateRefreshToken(const std::string& userId);
    
    /**
     * @brief 验证JWT Token
     * @param token JWT token字符串
     * @return 验证结果
     */
    JwtVerifyResult verifyToken(const std::string& token);
    
    /**
     * @brief 解析Token（不验证签名）
     * @param token JWT token字符串
     * @return 解析的Claims
     */
    JwtClaims parseToken(const std::string& token);
    
    /**
     * @brief 从Authorization头中提取token
     * @param authHeader Authorization头的值
     * @return 提取的token，如果格式不正确返回空字符串
     */
    std::string extractTokenFromHeader(const std::string& authHeader) const;
    
    /**
     * @brief 刷新Token
     * @param refreshToken 刷新token
     * @return 新的access token，如果刷新失败返回空字符串
     */
    std::string refreshAccessToken(const std::string& refreshToken);
    
    /**
     * @brief 获取当前时间戳（秒）
     */
    static int64_t getCurrentTimestamp();
    
    /**
     * @brief 设置配置
     */
    void setConfig(const JwtConfig& config) { config_ = config; }
    
    /**
     * @brief 获取配置
     */
    const JwtConfig& getConfig() const { return config_; }

private:
    /**
     * @brief Base64URL编码
     */
    static std::string base64UrlEncode(const std::string& data);
    
    /**
     * @brief Base64URL解码
     */
    static std::string base64UrlDecode(const std::string& data);
    
    /**
     * @brief 计算HMAC签名
     */
    std::string calculateHmacSignature(const std::string& data) const;
    
    /**
     * @brief 构建JWT头部
     */
    std::string buildHeader() const;
    
    /**
     * @brief 构建JWT负载
     */
    std::string buildPayload(const JwtClaims& claims) const;
    
    /**
     * @brief 从JSON解析Claims
     */
    JwtClaims parseClaimsFromJson(const std::string& json) const;
    
    /**
     * @brief 将Claims转换为JSON
     */
    std::string claimsToJson(const JwtClaims& claims) const;

private:
    JwtConfig config_;
};

} // namespace middleware
} // namespace http
