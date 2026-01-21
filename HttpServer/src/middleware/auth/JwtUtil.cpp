#include "../../../include/middleware/auth/JwtUtil.h"
#include <muduo/base/Logging.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace http 
{
namespace middleware 
{

JwtUtil::JwtUtil(const JwtConfig& config)
    : config_(config)
{
    LOG_INFO << "JwtUtil initialized with algorithm: " << config_.getAlgorithmName();
}

std::string JwtUtil::generateToken(const JwtClaims& claims)
{
    // 构建头部
    std::string header = buildHeader();
    std::string encodedHeader = base64UrlEncode(header);
    
    // 构建负载
    std::string payload = buildPayload(claims);
    std::string encodedPayload = base64UrlEncode(payload);
    
    // 构建签名输入
    std::string signatureInput = encodedHeader + "." + encodedPayload;
    
    // 计算签名
    std::string signature = calculateHmacSignature(signatureInput);
    std::string encodedSignature = base64UrlEncode(signature);
    
    return signatureInput + "." + encodedSignature;
}

std::string JwtUtil::generateAccessToken(
    const std::string& userId,
    const std::string& username,
    const std::vector<std::string>& roles,
    const std::vector<std::string>& permissions)
{
    JwtClaims claims;
    claims.subject = userId;
    claims.userId = userId;
    claims.username = username;
    claims.issuer = config_.issuer;
    claims.audience = config_.audience;
    claims.issuedAt = getCurrentTimestamp();
    claims.expiresAt = claims.issuedAt + config_.accessTokenExpiry;
    claims.roles = roles;
    claims.permissions = permissions;
    
    return generateToken(claims);
}

std::string JwtUtil::generateRefreshToken(const std::string& userId)
{
    JwtClaims claims;
    claims.subject = userId;
    claims.userId = userId;
    claims.issuer = config_.issuer;
    claims.audience = config_.audience;
    claims.issuedAt = getCurrentTimestamp();
    claims.expiresAt = claims.issuedAt + config_.refreshTokenExpiry;
    claims.jwtId = std::to_string(getCurrentTimestamp()) + "_" + userId;
    
    return generateToken(claims);
}

JwtVerifyResult JwtUtil::verifyToken(const std::string& token)
{
    try
    {
        // 分割token
        std::vector<std::string> parts;
        std::stringstream ss(token);
        std::string part;
        while (std::getline(ss, part, '.'))
        {
            parts.push_back(part);
        }
        
        if (parts.size() != 3)
        {
            return JwtVerifyResult::failure("Invalid token format");
        }
        
        // 验证签名
        std::string signatureInput = parts[0] + "." + parts[1];
        std::string expectedSignature = base64UrlEncode(calculateHmacSignature(signatureInput));
        
        if (parts[2] != expectedSignature)
        {
            return JwtVerifyResult::failure("Invalid signature");
        }
        
        // 解析payload
        std::string payload = base64UrlDecode(parts[1]);
        JwtClaims claims = parseClaimsFromJson(payload);
        
        // 验证过期时间
        if (config_.validateExpiry && claims.isExpired())
        {
            int64_t now = getCurrentTimestamp();
            if (now > claims.expiresAt + config_.clockSkewSeconds)
            {
                return JwtVerifyResult::failure("Token has expired");
            }
        }
        
        // 验证生效时间
        if (!claims.isActive())
        {
            int64_t now = getCurrentTimestamp();
            if (now < claims.notBefore - config_.clockSkewSeconds)
            {
                return JwtVerifyResult::failure("Token not yet valid");
            }
        }
        
        // 验证发行者
        if (config_.validateIssuer && !config_.issuer.empty())
        {
            if (claims.issuer != config_.issuer)
            {
                return JwtVerifyResult::failure("Invalid issuer");
            }
        }
        
        // 验证受众
        if (config_.validateAudience && !config_.audience.empty())
        {
            if (claims.audience != config_.audience)
            {
                return JwtVerifyResult::failure("Invalid audience");
            }
        }
        
        return JwtVerifyResult::success(claims);
    }
    catch (const std::exception& e)
    {
        return JwtVerifyResult::failure(std::string("Token verification failed: ") + e.what());
    }
}

JwtClaims JwtUtil::parseToken(const std::string& token)
{
    std::vector<std::string> parts;
    std::stringstream ss(token);
    std::string part;
    while (std::getline(ss, part, '.'))
    {
        parts.push_back(part);
    }
    
    if (parts.size() < 2)
    {
        throw std::runtime_error("Invalid token format");
    }
    
    std::string payload = base64UrlDecode(parts[1]);
    return parseClaimsFromJson(payload);
}

std::string JwtUtil::extractTokenFromHeader(const std::string& authHeader) const
{
    if (authHeader.empty())
    {
        return "";
    }
    
    // 检查前缀
    if (authHeader.substr(0, config_.tokenPrefix.length()) == config_.tokenPrefix)
    {
        return authHeader.substr(config_.tokenPrefix.length());
    }
    
    return authHeader;
}

std::string JwtUtil::refreshAccessToken(const std::string& refreshToken)
{
    auto result = verifyToken(refreshToken);
    if (!result.valid)
    {
        LOG_WARN << "Failed to refresh token: " << result.error;
        return "";
    }
    
    // 生成新的access token
    return generateAccessToken(
        result.claims.userId,
        result.claims.username,
        result.claims.roles,
        result.claims.permissions
    );
}

int64_t JwtUtil::getCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string JwtUtil::base64UrlEncode(const std::string& data)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    
    // 转换为URL安全的Base64
    std::replace(result.begin(), result.end(), '+', '-');
    std::replace(result.begin(), result.end(), '/', '_');
    
    // 移除填充
    result.erase(std::remove(result.begin(), result.end(), '='), result.end());
    
    return result;
}

std::string JwtUtil::base64UrlDecode(const std::string& data)
{
    std::string input = data;
    
    // 转换回标准Base64
    std::replace(input.begin(), input.end(), '-', '+');
    std::replace(input.begin(), input.end(), '_', '/');
    
    // 添加填充
    while (input.size() % 4 != 0)
    {
        input += '=';
    }
    
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    bmem = BIO_push(b64, bmem);
    
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    
    std::string result(input.size(), '\0');
    int decodedLen = BIO_read(bmem, &result[0], static_cast<int>(input.size()));
    
    BIO_free_all(bmem);
    
    if (decodedLen < 0)
    {
        throw std::runtime_error("Base64 decode failed");
    }
    
    result.resize(decodedLen);
    return result;
}

std::string JwtUtil::calculateHmacSignature(const std::string& data) const
{
    const EVP_MD* md = nullptr;
    
    switch (config_.algorithm)
    {
        case JwtAlgorithm::HS256:
            md = EVP_sha256();
            break;
        case JwtAlgorithm::HS384:
            md = EVP_sha384();
            break;
        case JwtAlgorithm::HS512:
            md = EVP_sha512();
            break;
        default:
            md = EVP_sha256();
            break;
    }
    
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultLen;
    
    HMAC(md, 
         config_.secretKey.data(), 
         static_cast<int>(config_.secretKey.size()),
         reinterpret_cast<const unsigned char*>(data.data()), 
         data.size(),
         result, 
         &resultLen);
    
    return std::string(reinterpret_cast<char*>(result), resultLen);
}

std::string JwtUtil::buildHeader() const
{
    json header;
    header["alg"] = config_.getAlgorithmName();
    header["typ"] = "JWT";
    return header.dump();
}

std::string JwtUtil::buildPayload(const JwtClaims& claims) const
{
    return claimsToJson(claims);
}

JwtClaims JwtUtil::parseClaimsFromJson(const std::string& jsonStr) const
{
    JwtClaims claims;
    
    try
    {
        json j = json::parse(jsonStr);
        
        if (j.contains("sub")) claims.subject = j["sub"].get<std::string>();
        if (j.contains("iss")) claims.issuer = j["iss"].get<std::string>();
        if (j.contains("aud")) claims.audience = j["aud"].get<std::string>();
        if (j.contains("exp")) claims.expiresAt = j["exp"].get<int64_t>();
        if (j.contains("iat")) claims.issuedAt = j["iat"].get<int64_t>();
        if (j.contains("nbf")) claims.notBefore = j["nbf"].get<int64_t>();
        if (j.contains("jti")) claims.jwtId = j["jti"].get<std::string>();
        
        if (j.contains("userId")) claims.userId = j["userId"].get<std::string>();
        if (j.contains("username")) claims.username = j["username"].get<std::string>();
        if (j.contains("email")) claims.email = j["email"].get<std::string>();
        
        if (j.contains("roles") && j["roles"].is_array())
        {
            for (const auto& role : j["roles"])
            {
                claims.roles.push_back(role.get<std::string>());
            }
        }
        
        if (j.contains("permissions") && j["permissions"].is_array())
        {
            for (const auto& perm : j["permissions"])
            {
                claims.permissions.push_back(perm.get<std::string>());
            }
        }
        
        if (j.contains("customData"))
        {
            claims.customData = j["customData"].dump();
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR << "Failed to parse JWT claims: " << e.what();
        throw;
    }
    
    return claims;
}

std::string JwtUtil::claimsToJson(const JwtClaims& claims) const
{
    json j;
    
    if (!claims.subject.empty()) j["sub"] = claims.subject;
    if (!claims.issuer.empty()) j["iss"] = claims.issuer;
    if (!claims.audience.empty()) j["aud"] = claims.audience;
    if (claims.expiresAt > 0) j["exp"] = claims.expiresAt;
    if (claims.issuedAt > 0) j["iat"] = claims.issuedAt;
    if (claims.notBefore > 0) j["nbf"] = claims.notBefore;
    if (!claims.jwtId.empty()) j["jti"] = claims.jwtId;
    
    if (!claims.userId.empty()) j["userId"] = claims.userId;
    if (!claims.username.empty()) j["username"] = claims.username;
    if (!claims.email.empty()) j["email"] = claims.email;
    
    if (!claims.roles.empty())
    {
        j["roles"] = claims.roles;
    }
    
    if (!claims.permissions.empty())
    {
        j["permissions"] = claims.permissions;
    }
    
    if (!claims.customData.empty())
    {
        try
        {
            j["customData"] = json::parse(claims.customData);
        }
        catch (...)
        {
            j["customData"] = claims.customData;
        }
    }
    
    return j.dump();
}

} // namespace middleware
} // namespace http
