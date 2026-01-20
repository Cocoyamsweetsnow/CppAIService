#include "../include/handlers/AIUploadSendHandler.h"


void AIUploadSendHandler::handle(const http::HttpRequest& req, http::HttpResponse* resp)
{
    try
    {
        LOG_INFO << "[ImageRecognizer] Request received";

        auto session = server_->getSessionManager()->getSession(req, resp);
        LOG_INFO << "session->getValue(\"isLoggedIn\") = " << session->getValue("isLoggedIn");
        if (session->getValue("isLoggedIn") != "true")
        {
            LOG_WARN << "[ImageRecognizer] Unauthorized request";
            json errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "Unauthorized";
            std::string errorBody = errorResp.dump(4);

            server_->packageResp(req.getVersion(), http::HttpResponse::k401Unauthorized,
                "Unauthorized", true, "application/json", errorBody.size(),
                errorBody, resp);
            return;
        }

        int userId = std::stoi(session->getValue("userId"));
        LOG_INFO << "[ImageRecognizer] User ID: " << userId;
        
        std::shared_ptr<ImageRecognizer> ImageRecognizerPtr;
        {
            std::lock_guard<std::mutex> lock(server_->mutexForImageRecognizerMap);
            if (server_->ImageRecognizerMap.find(userId) == server_->ImageRecognizerMap.end()) {
                LOG_INFO << "[ImageRecognizer] Creating new ImageRecognizer for user " << userId;
                server_->ImageRecognizerMap.emplace(
                    userId,
                    std::make_shared<ImageRecognizer>(
                        "../AIApps/ChatServer/resource/models/mobilenetv2-7.onnx",
                        "../AIApps/ChatServer/resource/models/imagenet_classes.txt"
                    )
                );
                LOG_INFO << "[ImageRecognizer] ImageRecognizer created successfully";
            }
            ImageRecognizerPtr = server_->ImageRecognizerMap[userId];
        }

        auto body = req.getBody();
        LOG_INFO << "[ImageRecognizer] Request body size: " << body.size();
        
        std::string filename;
        std::string imageBase64;
        if (!body.empty()) {
            auto j = json::parse(body);
            if (j.contains("filename")) filename = j["filename"];
            if (j.contains("image")) imageBase64 = j["image"];
        }
        if (imageBase64.empty())
        {
            throw std::runtime_error("No image data provided");
        }

        LOG_INFO << "[ImageRecognizer] Base64 data size: " << imageBase64.size();

        std::string decodedData = base64_decode(imageBase64);
        std::vector<uchar> imgData(decodedData.begin(), decodedData.end());
        
        LOG_INFO << "[ImageRecognizer] Decoded image size: " << imgData.size() << " bytes";
        LOG_INFO << "[ImageRecognizer] Starting prediction...";

        std::string className = ImageRecognizerPtr->PredictFromBuffer(imgData);
        
        LOG_INFO << "[ImageRecognizer] Prediction result: " << className;


        json successResp;
        successResp["success"] = "ok";
        successResp["filename"] = filename;
        successResp["class_name"] = className;

        successResp["confidence"] = 0.95; // todo:Calculating true confidence


        std::string successBody = successResp.dump(4);

        resp->setStatusLine(req.getVersion(), http::HttpResponse::k200Ok, "OK");
        resp->setCloseConnection(false);
        resp->setContentType("application/json");
        resp->setContentLength(successBody.size());
        resp->setBody(successBody);
        return;

    }
    catch (const std::exception& e)
    {

        json failureResp;
        failureResp["status"] = "error";
        failureResp["message"] = e.what();
        std::string failureBody = failureResp.dump(4);
        resp->setStatusLine(req.getVersion(), http::HttpResponse::k400BadRequest, "Bad Request");
        resp->setCloseConnection(true);
        resp->setContentType("application/json");
        resp->setContentLength(failureBody.size());
        resp->setBody(failureBody);
    }
}



