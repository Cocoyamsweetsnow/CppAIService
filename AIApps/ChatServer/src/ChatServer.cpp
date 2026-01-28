#include "../include/handlers/ChatLoginHandler.h"
#include "../include/handlers/ChatRegisterHandler.h"
#include "../include/handlers/ChatLogoutHandler.h"
#include"../include/handlers/ChatHandler.h"
#include"../include/handlers/ChatEntryHandler.h"
#include"../include/handlers/ChatSendHandler.h"
#include"../include/handlers/AIMenuHandler.h"
#include"../include/handlers/AIUploadSendHandler.h"
#include"../include/handlers/AIUploadHandler.h"
#include"../include/handlers/ChatHistoryHandler.h"

#include"../include/handlers/ChatCreateAndSendHandler.h"
#include"../include/handlers/ChatSessionsHandler.h"
#include"../include/handlers/ChatSpeechHandler.h"

// 认证相关Handler
#include"../include/handlers/AuthRefreshHandler.h"
#include"../include/handlers/AuthUserInfoHandler.h"

#include "../include/ChatServer.h"
#include "../../../HttpServer/include/http/HttpRequest.h"
#include "../../../HttpServer/include/http/HttpResponse.h"
#include "../../../HttpServer/include/http/HttpServer.h"



using namespace http;


ChatServer::ChatServer(int port,
    const std::string& name,
    muduo::net::TcpServer::Option option)
    : httpServer_(port, name, option)
{
    initialize();
}

void ChatServer::initialize() {
    std::cout << "ChatServer initialize start  ! " << std::endl;
	http::MysqlUtil::init("tcp://127.0.0.1:3306", "root", "123456", "ChatHttpServer", 5);

    initializeSession();

    initializeMiddleware();

    initializeRouter();
}

void ChatServer::initChatMessage() {

    std::cout << "initChatMessage start ! " << std::endl;
    readDataFromMySQL();
    std::cout << "initChatMessage success ! " << std::endl;
}

void ChatServer::readDataFromMySQL() {


    std::string sql = "SELECT id, username,session_id, is_user, content, ts FROM chat_message ORDER BY ts ASC, id ASC";

    sql::ResultSet* res;
    try {
        res = mysqlUtil_.executeQuery(sql);
    }
    catch (const std::exception& e) {
        std::cerr << "MySQL query failed: " << e.what() << std::endl;
        return;
    }

    while (res->next()) {
        long long user_id = 0;
        std::string session_id ;  
        std::string username, content;
        long long ts = 0;
        int is_user = 1;

        try {
            user_id    = res->getInt64("id");       
            session_id = res->getString("session_id");  
            username   = res->getString("username");
            content    = res->getString("content");
            ts         = res->getInt64("ts");
            is_user    = res->getInt("is_user");
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to read row: " << e.what() << std::endl;
            continue; 
        }

        auto& userSessions = chatInformation[user_id];

        std::shared_ptr<AIHelper> helper;
        auto itSession = userSessions.find(session_id);
        if (itSession == userSessions.end()) {
            helper = std::make_shared<AIHelper>();
            userSessions[session_id] = helper;
			sessionsIdsMap[user_id].push_back(session_id);
        } else {
            helper = itSession->second;
        }

        helper->restoreMessage(content, ts);
    }

    std::cout << "readDataFromMySQL finished" << std::endl;
}



void ChatServer::setThreadNum(int numThreads) {
    httpServer_.setThreadNum(numThreads);
}


void ChatServer::start() {
    httpServer_.start();
}


void ChatServer::initializeRouter() {
    // ==================== 公开路由（不需要认证）====================
    
    // 入口页面
    httpServer_.Get("/", std::make_shared<ChatEntryHandler>(this));
    httpServer_.Get("/entry", std::make_shared<ChatEntryHandler>(this));
    
    // 认证相关路由
    httpServer_.Post("/login", std::make_shared<ChatLoginHandler>(this));
    httpServer_.Post("/register", std::make_shared<ChatRegisterHandler>(this));
    httpServer_.Post("/api/auth/refresh", std::make_shared<AuthRefreshHandler>(this));
    
    // 菜单和上传页面
    httpServer_.Get("/menu", std::make_shared<AIMenuHandler>(this));
    httpServer_.Get("/upload", std::make_shared<AIUploadHandler>(this));
    
    // ==================== 需要认证的路由 ====================
    
    // 用户信息
    httpServer_.Get("/api/auth/userinfo", std::make_shared<AuthUserInfoHandler>(this));
    httpServer_.Post("/user/logout", std::make_shared<ChatLogoutHandler>(this));
    
    // 聊天功能
    httpServer_.Get("/chat", std::make_shared<ChatHandler>(this));
    httpServer_.Post("/chat/send", std::make_shared<ChatSendHandler>(this));
    httpServer_.Post("/chat/history", std::make_shared<ChatHistoryHandler>(this));
    httpServer_.Post("/chat/send-new-session", std::make_shared<ChatCreateAndSendHandler>(this));
    httpServer_.Get("/chat/sessions", std::make_shared<ChatSessionsHandler>(this));
    httpServer_.Post("/chat/tts", std::make_shared<ChatSpeechHandler>(this));
    
    // 上传功能
    httpServer_.Post("/upload/send", std::make_shared<AIUploadSendHandler>(this));
    
    LOG_INFO << "All routes registered";
}

void ChatServer::initializeSession() {

    auto sessionStorage = std::make_unique<http::session::MemorySessionStorage>();

    auto sessionManager = std::make_unique<http::session::SessionManager>(std::move(sessionStorage));

    setSessionManager(std::move(sessionManager));
}

void ChatServer::initializeMiddleware() {
    // 1. CORS中间件（最先处理）
    auto corsMiddleware = std::make_shared<http::middleware::CorsMiddleware>();
    httpServer_.addMiddleware(corsMiddleware);
    
    // 2. 限流中间件
    setupRateLimitMiddleware();
    
    // 3. Gzip压缩中间件
    setupGzipMiddleware();
    
    // 4. 初始化角色和权限管理
    initializeRoleManager();
    
    // 5. 认证中间件
    setupAuthMiddleware();
    
    // 6. 授权中间件
    setupAuthorizationMiddleware();
    
    LOG_INFO << "All middleware initialized successfully";
}

void ChatServer::initializeRoleManager() {
    using namespace http::middleware;
    
    // 获取角色管理器单例
    RoleManager& roleManager = RoleManager::getInstance();
    
    // 初始化默认角色和权限
    roleManager.initializeDefaults();
    
    // 添加应用特定的权限
    roleManager.createResourcePermissions("chat");
    roleManager.createResourcePermissions("upload");
    roleManager.createResourcePermissions("session");
    
    // 创建普通用户角色的权限
    roleManager.addPermissionToRole(Roles::USER, "chat:create");
    roleManager.addPermissionToRole(Roles::USER, "chat:read");
    roleManager.addPermissionToRole(Roles::USER, "upload:create");
    roleManager.addPermissionToRole(Roles::USER, "session:read");
    roleManager.addPermissionToRole(Roles::USER, "session:create");
    
    LOG_INFO << "RoleManager initialized with custom permissions";
}

void ChatServer::setupRateLimitMiddleware() {
    using namespace http::middleware;
    
    // 配置限流中间件
    RateLimitConfig config;
    config.algorithm = RateLimitAlgorithm::TOKEN_BUCKET;
    config.maxRequests = 100;           // 每个时间窗口最大100个请求
    config.windowSizeSeconds = 60;       // 60秒时间窗口
    config.tokenRefillRate = 10.0;       // 每秒补充10个令牌
    config.bucketCapacity = 100;         // 桶容量100
    config.perIpLimit = true;            // 按IP限流
    config.limitExceededMessage = "请求过于频繁，请稍后再试";
    
    // 白名单IP（本地开发）
    config.whitelistIps = {"127.0.0.1", "::1", "localhost"};
    
    rateLimitMiddleware_ = std::make_shared<RateLimitMiddleware>(config);
    httpServer_.addMiddleware(rateLimitMiddleware_);
    
    LOG_INFO << "RateLimitMiddleware configured";
}

void ChatServer::setupGzipMiddleware() {
    using namespace http::middleware;
    
    // 配置Gzip压缩中间件
    GzipConfig config;
    config.compressionLevel = static_cast<int>(CompressionLevel::DEFAULT);
    config.minCompressSize = 1024;       // 大于1KB才压缩
    config.maxCompressSize = 5 * 1024 * 1024;  // 最大5MB
    config.enabled = true;
    
    gzipMiddleware_ = std::make_shared<GzipMiddleware>(config);
    httpServer_.addMiddleware(gzipMiddleware_);
    
    LOG_INFO << "GzipMiddleware configured";
}

void ChatServer::setupAuthMiddleware() {
    using namespace http::middleware;
    
    // 配置JWT
    JwtConfig jwtConfig;
    jwtConfig.secretKey = "ChatServer-Secret-Key-2024-Very-Long-And-Secure";
    jwtConfig.issuer = "ChatServer";
    jwtConfig.audience = "ChatClient";
    jwtConfig.accessTokenExpiry = 7200;      // 2小时
    jwtConfig.refreshTokenExpiry = 604800;   // 7天
    jwtConfig.algorithm = JwtAlgorithm::HS256;
    
    // 配置认证中间件
    AuthConfig authConfig;
    authConfig.authType = AuthType::JWT;
    authConfig.jwtConfig = jwtConfig;
    authConfig.enabled = true;
    authConfig.unauthorizedMessage = "请先登录";
    
    // 配置不需要认证的路径（白名单）
    // 注意：这些页面内部会自行检查认证状态
    authConfig.excludedPaths = {
        // 入口和静态页面
        PathRule("/", false),
        PathRule("/entry", false),
        PathRule("/menu", false),
        PathRule("/upload", false),
        PathRule("/chat", false),  // 聊天页面（页面内部检查认证）
        
        // 登录注册相关
        PathRule("/login", false),
        PathRule("/register", false),
        PathRule("/api/auth/*", false),
        
        // 健康检查
        PathRule("/health", false),
        PathRule("/ping", false),
        
        // 静态资源
        PathRule("/static/*", false),
        PathRule("/public/*", false),
        PathRule("*.html", false),
        PathRule("*.css", false),
        PathRule("*.js", false),
        PathRule("*.ico", false)
    };
    
    authMiddleware_ = std::make_shared<AuthMiddleware>(authConfig);
    
    // 设置用户验证回调（用于Basic认证，如果需要的话）
    authMiddleware_->setUserValidator([this](const std::string& username, const std::string& password) -> std::string {
        std::string sql = "SELECT id FROM users WHERE username = ? AND password = ?";
        auto res = mysqlUtil_.executeQuery(sql, username, password);
        if (res && res->next()) {
            return std::to_string(res->getInt("id"));
        }
        return "";
    });
    
    httpServer_.addMiddleware(authMiddleware_);
    
    LOG_INFO << "AuthMiddleware configured with JWT authentication";
}

void ChatServer::setupAuthorizationMiddleware() {
    using namespace http::middleware;
    
    // 配置授权中间件
    AuthorizationConfig authzConfig;
    authzConfig.enabled = true;
    authzConfig.defaultAllow = true;  // 默认允许（认证通过的用户）
    authzConfig.useRoleManager = true;
    authzConfig.forbiddenMessage = "权限不足，无法访问此资源";
    
    authorizationMiddleware_ = std::make_shared<AuthorizationMiddleware>(authzConfig);
    
    // 配置需要特定角色的路径
    // 管理员路径
    authorizationMiddleware_->requireRole("/admin/*", Roles::ADMIN);
    authorizationMiddleware_->requireRole("/api/admin/*", Roles::ADMIN);
    
    // 配置需要特定权限的路径
    // 聊天功能需要chat权限
    authorizationMiddleware_->requireResourcePermission("/chat/send", "chat", "create", {"POST"});
    authorizationMiddleware_->requireResourcePermission("/chat/send-new-session", "chat", "create", {"POST"});
    authorizationMiddleware_->requireResourcePermission("/chat/history", "chat", "read", {"POST"});
    authorizationMiddleware_->requireResourcePermission("/chat/sessions", "session", "read", {"GET"});
    
    // 上传功能需要upload权限
    authorizationMiddleware_->requireResourcePermission("/upload/send", "upload", "create", {"POST"});
    
    // TTS功能
    authorizationMiddleware_->requireResourcePermission("/chat/tts", "chat", "read", {"POST"});
    
    httpServer_.addMiddleware(authorizationMiddleware_);
    
    LOG_INFO << "AuthorizationMiddleware configured with RBAC rules";
}


void ChatServer::packageResp(const std::string& version,
    http::HttpResponse::HttpStatusCode statusCode,
    const std::string& statusMsg,
    bool close,
    const std::string& contentType,
    int contentLen,
    const std::string& body,
    http::HttpResponse* resp)
{
    if (resp == nullptr)
    {
        LOG_ERROR << "Response pointer is null";
        return;
    }

    try
    {
        resp->setVersion(version);
        resp->setStatusCode(statusCode);
        resp->setStatusMessage(statusMsg);
        resp->setCloseConnection(close);
        resp->setContentType(contentType);
        resp->setContentLength(contentLen);
        resp->setBody(body);

        LOG_INFO << "Response packaged successfully";
    }
    catch (const std::exception& e)
    {
        LOG_ERROR << "Error in packageResp: " << e.what();

        resp->setStatusCode(http::HttpResponse::k500InternalServerError);
        resp->setStatusMessage("Internal Server Error");
        resp->setCloseConnection(true);
    }
}
