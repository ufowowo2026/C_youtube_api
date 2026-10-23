#include "crow.h"
#include <curl/curl.h>
#include <libpq-fe.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace {

bool is_valid_video_id(const std::string& id) {
    static const std::regex video_id_pattern("^[a-zA-Z0-9_-]{11}$");
    return std::regex_match(id, video_id_pattern);
}

size_t append_response_body(char* data, size_t size, size_t count, void* user_data) {
    const size_t bytes = size * count;
    static_cast<std::string*>(user_data)->append(data, bytes);
    return bytes;
}

crow::response json_error(int status, const std::string& message) {
    crow::json::wvalue body;
    body["error"] = message;
    crow::response response(status, body.dump());
    response.set_header("Content-Type", "application/json; charset=utf-8");
    response.set_header("Cache-Control", "no-store");
    return response;
}

std::string escape_url_component(CURL* curl, const std::string& value) {
    char* escaped = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
    if (escaped == nullptr) {
        return {};
    }

    std::string result(escaped);
    curl_free(escaped);
    return result;
}

struct YouTubeResponse {
    CURLcode request_status;
    long http_status;
    std::string body;
};

struct YouTubeApiError {
    std::string status;
    std::string reason;
    std::string message;
};

std::string read_json_string(const crow::json::rvalue& object, const char* key) {
    if (!object || object.t() != crow::json::type::Object || !object.has(key)) {
        return {};
    }

    const auto& value = object[key];
    if (value.t() != crow::json::type::String) {
        return {};
    }
    return std::string(value.s());
}

YouTubeApiError parse_youtube_api_error(const std::string& body) {
    const auto document = crow::json::load(body);
    if (!document || document.t() != crow::json::type::Object || !document.has("error")) {
        return {};
    }

    const auto& error = document["error"];
    if (error.t() != crow::json::type::Object) {
        return {};
    }

    YouTubeApiError details{
        read_json_string(error, "status"),
        {},
        read_json_string(error, "message")
    };

    if (error.has("errors")) {
        const auto& errors = error["errors"];
        if (errors.t() == crow::json::type::List && errors.size() > 0) {
            details.reason = read_json_string(errors[0], "reason");
        }
    }
    return details;
}

std::string sanitize_api_error_detail(std::string value, const std::string& api_key) {
    if (!api_key.empty()) {
        size_t position = 0;
        while ((position = value.find(api_key, position)) != std::string::npos) {
            value.replace(position, api_key.size(), "[redacted]");
            position += sizeof("[redacted]") - 1;
        }
    }

    for (char& character : value) {
        if (character == '\r' || character == '\n' || character == '\t') {
            character = ' ';
        }
    }
    constexpr size_t max_detail_length = 500;
    if (value.size() > max_detail_length) {
        value.resize(max_detail_length);
        value += "...";
    }
    return value;
}

std::string environment_value(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

using PgResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

class PgConnection {
public:
    PgConnection() : connection_(PQconnectdb(environment_value("DATABASE_URL").c_str())) {}
    ~PgConnection() {
        if (connection_ != nullptr) {
            PQfinish(connection_);
        }
    }
    PgConnection(const PgConnection&) = delete;
    PgConnection& operator=(const PgConnection&) = delete;

    bool connected() const {
        return connection_ != nullptr && PQstatus(connection_) == CONNECTION_OK;
    }

    PGconn* get() const {
        return connection_;
    }

private:
    PGconn* connection_;
};

PgResult execute_sql(
    PGconn* connection,
    const std::string& sql,
    const std::vector<std::string>& parameters = {}) {
    std::vector<const char*> values;
    values.reserve(parameters.size());
    for (const auto& parameter : parameters) {
        values.push_back(parameter.c_str());
    }

    PGresult* result = PQexecParams(
        connection,
        sql.c_str(),
        static_cast<int>(values.size()),
        nullptr,
        values.empty() ? nullptr : values.data(),
        nullptr,
        nullptr,
        0);
    return PgResult(result, &PQclear);
}

void log_database_result_error(const char* context, PGresult* result) {
    std::cerr << context;
    if (result != nullptr) {
        const char* sql_state = PQresultErrorField(result, PG_DIAG_SQLSTATE);
        if (sql_state != nullptr) std::cerr << " SQLSTATE=" << sql_state;
    }
    std::cerr << std::endl;
}

bool ensure_auth_schema(PGconn* connection) {
    static std::mutex schema_mutex;
    static bool schema_ready = false;
    std::lock_guard<std::mutex> lock(schema_mutex);
    if (schema_ready) return true;

    static const char* statements[] = {
        "CREATE TABLE IF NOT EXISTS google_accounts ("
        "google_sub TEXT PRIMARY KEY, email TEXT NOT NULL, "
        "refresh_token_ciphertext TEXT NOT NULL, refresh_token_iv TEXT NOT NULL, "
        "refresh_token_tag TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS web_sessions ("
        "session_hash TEXT PRIMARY KEY, google_sub TEXT NOT NULL REFERENCES google_accounts(google_sub) ON DELETE CASCADE, "
        "csrf_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)",
        "CREATE INDEX IF NOT EXISTS web_sessions_expiry_idx ON web_sessions(expires_at)",
        "CREATE TABLE IF NOT EXISTS oauth_states ("
        "state_hash TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL)"
    };

    for (const char* statement : statements) {
        PgResult result = execute_sql(connection, statement);
        if (!result || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
            log_database_result_error("無法初始化 OAuth 資料表。", result.get());
            return false;
        }
    }
    schema_ready = true;
    return true;
}

std::string hex_encode(const unsigned char* bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(length * 2);
    for (size_t index = 0; index < length; ++index) {
        encoded.push_back(digits[bytes[index] >> 4]);
        encoded.push_back(digits[bytes[index] & 0x0f]);
    }
    return encoded;
}

bool hex_decode(const std::string& value, unsigned char* output, size_t output_size) {
    if (value.size() != output_size * 2) {
        return false;
    }
    auto hex_value = [](char character) -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        if (character >= 'A' && character <= 'F') return character - 'A' + 10;
        return -1;
    };
    for (size_t index = 0; index < output_size; ++index) {
        const int high = hex_value(value[index * 2]);
        const int low = hex_value(value[index * 2 + 1]);
        if (high < 0 || low < 0) return false;
        output[index] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

std::string sha256_hex(const std::string& value) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), digest.data());
    return hex_encode(digest.data(), digest.size());
}

bool random_url_token(std::string& token) {
    std::array<unsigned char, 32> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return false;
    }
    std::array<unsigned char, 4 * ((32 + 2) / 3) + 1> encoded{};
    const int encoded_length = EVP_EncodeBlock(encoded.data(), bytes.data(), static_cast<int>(bytes.size()));
    if (encoded_length <= 0) {
        return false;
    }
    token.assign(reinterpret_cast<const char*>(encoded.data()), static_cast<size_t>(encoded_length));
    for (char& character : token) {
        if (character == '+') character = '-';
        else if (character == '/') character = '_';
    }
    while (!token.empty() && token.back() == '=') token.pop_back();
    return true;
}

bool read_encryption_key(std::array<unsigned char, 32>& key) {
    const std::string configured_key = environment_value("TOKEN_ENCRYPTION_KEY");
    return hex_decode(configured_key, key.data(), key.size());
}

bool encrypt_secret(
    const std::string& plaintext,
    std::string& ciphertext_hex,
    std::string& iv_hex,
    std::string& tag_hex) {
    std::array<unsigned char, 32> key{};
    std::array<unsigned char, 12> iv{};
    std::array<unsigned char, 16> tag{};
    if (!read_encryption_key(key) || RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        return false;
    }

    EVP_CIPHER_CTX* raw_context = EVP_CIPHER_CTX_new();
    if (raw_context == nullptr) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(raw_context, &EVP_CIPHER_CTX_free);
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int output_length = 0;
    int final_length = 0;
    const bool encrypted =
        EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
        EVP_EncryptUpdate(
            context.get(),
            ciphertext.data(),
            &output_length,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(context.get(), ciphertext.data() + output_length, &final_length) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
    if (!encrypted) return false;

    ciphertext_hex = hex_encode(ciphertext.data(), static_cast<size_t>(output_length + final_length));
    iv_hex = hex_encode(iv.data(), iv.size());
    tag_hex = hex_encode(tag.data(), tag.size());
    return true;
}

bool decrypt_secret(
    const std::string& ciphertext_hex,
    const std::string& iv_hex,
    const std::string& tag_hex,
    std::string& plaintext) {
    if (ciphertext_hex.size() % 2 != 0) return false;
    std::array<unsigned char, 32> key{};
    std::array<unsigned char, 12> iv{};
    std::array<unsigned char, 16> tag{};
    if (!read_encryption_key(key) ||
        !hex_decode(iv_hex, iv.data(), iv.size()) ||
        !hex_decode(tag_hex, tag.data(), tag.size())) {
        return false;
    }
    std::vector<unsigned char> ciphertext(ciphertext_hex.size() / 2);
    if (!hex_decode(ciphertext_hex, ciphertext.data(), ciphertext.size())) return false;

    EVP_CIPHER_CTX* raw_context = EVP_CIPHER_CTX_new();
    if (raw_context == nullptr) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(raw_context, &EVP_CIPHER_CTX_free);
    std::vector<unsigned char> decoded(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int output_length = 0;
    int final_length = 0;
    const bool initialized =
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
        EVP_DecryptUpdate(
            context.get(),
            decoded.data(),
            &output_length,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1 &&
        EVP_DecryptFinal_ex(context.get(), decoded.data() + output_length, &final_length) == 1;
    if (!initialized) return false;

    plaintext.assign(reinterpret_cast<const char*>(decoded.data()), static_cast<size_t>(output_length + final_length));
    return true;
}

std::string url_encode(CURL* curl, const std::string& value) {
    char* escaped = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
    if (escaped == nullptr) return {};
    std::string result(escaped);
    curl_free(escaped);
    return result;
}

YouTubeResponse request_http(
    const std::string& url,
    const std::string& method,
    const std::string& body = {},
    const std::string& bearer_token = {},
    const std::string& content_type = {}) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) return {CURLE_FAILED_INIT, 0, {}};

    YouTubeResponse result{CURLE_OK, 0, {}};
    curl_slist* headers = nullptr;
    if (!bearer_token.empty()) {
        headers = curl_slist_append(headers, ("Authorization: Bearer " + bearer_token).c_str());
    }
    if (!content_type.empty()) {
        headers = curl_slist_append(headers, ("Content-Type: " + content_type).c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (headers != nullptr) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (method == "POST" || method == "PUT" || !body.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }

    result.request_status = curl_easy_perform(curl);
    if (result.request_status == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_status);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result;
}

std::string form_encode(const std::vector<std::pair<std::string, std::string>>& fields) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) return {};
    std::string form;
    for (const auto& field : fields) {
        const std::string name = url_encode(curl, field.first);
        const std::string value = url_encode(curl, field.second);
        if (name.empty() || value.empty()) {
            curl_easy_cleanup(curl);
            return {};
        }
        if (!form.empty()) form += '&';
        form += name + "=" + value;
    }
    curl_easy_cleanup(curl);
    return form;
}

struct AccountSession {
    std::string google_sub;
    std::string email;
    std::string csrf_hash;
};

std::string cookie_value(const crow::request& request, const std::string& name) {
    const std::string cookies = request.get_header_value("Cookie");
    size_t start = 0;
    while (start < cookies.size()) {
        const size_t end = cookies.find(';', start);
        const std::string part = cookies.substr(start, end == std::string::npos ? end : end - start);
        const size_t equals = part.find('=');
        if (equals != std::string::npos) {
            size_t key_start = part.find_first_not_of(' ');
            if (key_start == std::string::npos) key_start = part.size();
            if (part.substr(key_start, equals - key_start) == name) {
                return part.substr(equals + 1);
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

bool lookup_session(PGconn* connection, const crow::request& request, AccountSession& session) {
    const std::string session_cookie = cookie_value(request, "app_session");
    if (session_cookie.empty()) return false;
    PgResult result = execute_sql(
        connection,
        "SELECT a.google_sub, a.email, s.csrf_hash FROM web_sessions s "
        "JOIN google_accounts a ON a.google_sub=s.google_sub "
        "WHERE s.session_hash=$1 AND s.expires_at > NOW()",
        {sha256_hex(session_cookie)});
    if (!result || PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) != 1) {
        if (!result || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
            log_database_result_error("無法查詢登入工作階段。", result.get());
        }
        return false;
    }
    session.google_sub = PQgetvalue(result.get(), 0, 0);
    session.email = PQgetvalue(result.get(), 0, 1);
    session.csrf_hash = PQgetvalue(result.get(), 0, 2);
    return true;
}

bool validate_csrf(const crow::request& request, const AccountSession& session) {
    const std::string supplied = request.get_header_value("X-CSRF-Token");
    if (supplied.empty()) return false;
    const std::string supplied_hash = sha256_hex(supplied);
    return supplied_hash.size() == session.csrf_hash.size() &&
        CRYPTO_memcmp(supplied_hash.data(), session.csrf_hash.data(), supplied_hash.size()) == 0;
}

crow::response authentication_required() {
    return json_error(401, "請先使用 Google 帳戶登入並授權 YouTube 播放清單。");
}

crow::response database_unavailable(PGconn* connection = nullptr) {
    if (connection != nullptr && PQstatus(connection) != CONNECTION_OK) {
        std::cerr << "OAuth database connection failed; verify DATABASE_URL, the Render Postgres status, and network access."
                  << std::endl;
    } else {
        std::cerr << "OAuth database operation failed; check the preceding PostgreSQL diagnostic and database availability."
                  << std::endl;
    }
    return json_error(503, "登入服務暫時無法使用，請稍後再試。");
}

YouTubeResponse request_youtube_api(
    const std::string& endpoint,
    const std::vector<std::pair<std::string, std::string>>& parameters,
    const std::string& api_key);

YouTubeResponse request_youtube_api(
    const std::string& endpoint,
    const std::vector<std::pair<std::string, std::string>>& parameters,
    const std::string& api_key) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        return {CURLE_FAILED_INIT, 0, {}};
    }

    std::string url = "https://www.googleapis.com/youtube/v3/" + endpoint + "?";
    for (const auto& parameter : parameters) {
        const std::string name = escape_url_component(curl, parameter.first);
        const std::string value = escape_url_component(curl, parameter.second);
        if (name.empty() || value.empty()) {
            curl_easy_cleanup(curl);
            return {CURLE_URL_MALFORMAT, 0, {}};
        }
        if (url.back() != '?') {
            url += '&';
        }
        url += name + "=" + value;
    }

    const std::string escaped_key = escape_url_component(curl, api_key);
    if (escaped_key.empty()) {
        curl_easy_cleanup(curl);
        return {CURLE_URL_MALFORMAT, 0, {}};
    }
    if (url.back() != '?') {
        url += '&';
    }
    url += "key=" + escaped_key;

    YouTubeResponse result{CURLE_OK, 0, {}};
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    result.request_status = curl_easy_perform(curl);
    if (result.request_status == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_status);
    }
    curl_easy_cleanup(curl);
    return result;
}

crow::response forward_youtube_response(const YouTubeResponse& result, const std::string& api_key) {
    if (result.request_status != CURLE_OK) {
        std::cerr << "YouTube API 請求失敗：" << curl_easy_strerror(result.request_status) << std::endl;
        return json_error(502, "無法連線至 YouTube 服務，請稍後再試。");
    }
    if (result.http_status < 200 || result.http_status >= 300) {
        const YouTubeApiError details = parse_youtube_api_error(result.body);
        const std::string status = sanitize_api_error_detail(details.status, api_key);
        const std::string reason = sanitize_api_error_detail(details.reason, api_key);
        const std::string message = sanitize_api_error_detail(details.message, api_key);

        std::cerr << "YouTube API 回傳 HTTP " << result.http_status;
        if (!status.empty()) {
            std::cerr << "; status=" << status;
        }
        if (!reason.empty()) {
            std::cerr << "; reason=" << reason;
        }
        if (!message.empty()) {
            std::cerr << "; message=" << message;
        }
        std::cerr << std::endl;

        std::string client_message = "YouTube API 回傳 HTTP " + std::to_string(result.http_status);
        if (!reason.empty()) {
            client_message += " (" + reason + ")";
        } else if (!status.empty()) {
            client_message += " (" + status + ")";
        }
        if (!message.empty()) {
            client_message += "：" + message;
        }
        return json_error(502, client_message);
    }

    crow::response response(result.body);
    response.set_header("Content-Type", "application/json; charset=utf-8");
    return response;
}

crow::response handle_youtube_api(
    const std::string& endpoint,
    const std::vector<std::pair<std::string, std::string>>& parameters) {
    const char* api_key = std::getenv("YOUTUBE_API_KEY");
    if (api_key == nullptr || *api_key == '\0') {
        return json_error(503, "伺服器尚未設定 YouTube Data API 金鑰。");
    }

    const auto result = request_youtube_api(endpoint, parameters, api_key);
    if (result.request_status == CURLE_FAILED_INIT) {
        std::cerr << "無法建立 YouTube API HTTP 用戶端。" << std::endl;
        return json_error(500, "伺服器暫時無法處理要求，請稍後再試。");
    }
    return forward_youtube_response(result, api_key);
}

std::vector<std::string> oauth_configuration_issues() {
    std::vector<std::string> issues;
    for (const char* name : {
             "DATABASE_URL",
             "GOOGLE_CLIENT_ID",
             "GOOGLE_CLIENT_SECRET",
             "GOOGLE_REDIRECT_URI"}) {
        if (environment_value(name).empty()) {
            issues.push_back(std::string(name) + " is not set.");
        }
    }

    std::array<unsigned char, 32> key{};
    const std::string configured_key = environment_value("TOKEN_ENCRYPTION_KEY");
    if (configured_key.empty()) {
        issues.push_back("TOKEN_ENCRYPTION_KEY is not set.");
    } else if (!read_encryption_key(key)) {
        issues.push_back("TOKEN_ENCRYPTION_KEY must be exactly 64 hexadecimal characters.");
    }
    return issues;
}

void log_oauth_configuration_issues(const std::vector<std::string>& issues) {
    for (const auto& issue : issues) {
        std::cerr << "OAuth configuration error: " << issue << std::endl;
    }
}

bool oauth_configuration_ready() {
    return oauth_configuration_issues().empty();
}

bool create_oauth_state(PGconn* connection, const std::string& state) {
    PgResult cleanup = execute_sql(connection, "DELETE FROM oauth_states WHERE expires_at <= NOW()");
    if (!cleanup || PQresultStatus(cleanup.get()) != PGRES_COMMAND_OK) return false;
    PgResult result = execute_sql(
        connection,
        "INSERT INTO oauth_states (state_hash, expires_at) VALUES ($1, NOW() + INTERVAL '10 minutes')",
        {sha256_hex(state)});
    return result && PQresultStatus(result.get()) == PGRES_COMMAND_OK;
}

bool consume_oauth_state(PGconn* connection, const std::string& state) {
    PgResult result = execute_sql(
        connection,
        "DELETE FROM oauth_states WHERE state_hash=$1 AND expires_at > NOW()",
        {sha256_hex(state)});
    return result && PQresultStatus(result.get()) == PGRES_COMMAND_OK &&
        std::string(PQcmdTuples(result.get())) == "1";
}

YouTubeResponse exchange_oauth_code(const std::string& code) {
    const std::string form = form_encode({
        {"code", code},
        {"client_id", environment_value("GOOGLE_CLIENT_ID")},
        {"client_secret", environment_value("GOOGLE_CLIENT_SECRET")},
        {"redirect_uri", environment_value("GOOGLE_REDIRECT_URI")},
        {"grant_type", "authorization_code"}
    });
    if (form.empty()) return {CURLE_FAILED_INIT, 0, {}};
    return request_http(
        "https://oauth2.googleapis.com/token",
        "POST",
        form,
        {},
        "application/x-www-form-urlencoded");
}

bool fetch_google_identity(const std::string& access_token, std::string& google_sub, std::string& email) {
    const YouTubeResponse response = request_http(
        "https://openidconnect.googleapis.com/v1/userinfo",
        "GET",
        {},
        access_token);
    if (response.request_status != CURLE_OK || response.http_status < 200 || response.http_status >= 300) {
        std::cerr << "無法取得 Google 帳戶資訊；HTTP " << response.http_status;
        if (response.request_status != CURLE_OK) std::cerr << "; " << curl_easy_strerror(response.request_status);
        std::cerr << std::endl;
        return false;
    }
    const auto identity = crow::json::load(response.body);
    if (!identity || identity.t() != crow::json::type::Object) return false;
    google_sub = read_json_string(identity, "sub");
    email = read_json_string(identity, "email");
    return !google_sub.empty();
}

bool save_google_account(
    PGconn* connection,
    const std::string& google_sub,
    const std::string& email,
    const std::string& refresh_token) {
    std::string ciphertext;
    std::string iv;
    std::string tag;
    if (!refresh_token.empty() && !encrypt_secret(refresh_token, ciphertext, iv, tag)) {
        std::cerr << "無法加密 Google OAuth refresh token；請檢查 TOKEN_ENCRYPTION_KEY。" << std::endl;
        return false;
    }

    if (refresh_token.empty()) {
        PgResult existing = execute_sql(
            connection,
            "SELECT 1 FROM google_accounts WHERE google_sub=$1",
            {google_sub});
        if (!existing || PQresultStatus(existing.get()) != PGRES_TUPLES_OK || PQntuples(existing.get()) != 1) {
            std::cerr << "Google 未提供 refresh token；請重新授權並同意離線存取。" << std::endl;
            return false;
        }
    }

    PgResult result = execute_sql(
        connection,
        "INSERT INTO google_accounts "
        "(google_sub,email,refresh_token_ciphertext,refresh_token_iv,refresh_token_tag) "
        "VALUES ($1,$2,$3,$4,$5) ON CONFLICT (google_sub) DO UPDATE SET "
        "email=EXCLUDED.email, "
        "refresh_token_ciphertext=CASE WHEN EXCLUDED.refresh_token_ciphertext='' THEN google_accounts.refresh_token_ciphertext ELSE EXCLUDED.refresh_token_ciphertext END, "
        "refresh_token_iv=CASE WHEN EXCLUDED.refresh_token_ciphertext='' THEN google_accounts.refresh_token_iv ELSE EXCLUDED.refresh_token_iv END, "
        "refresh_token_tag=CASE WHEN EXCLUDED.refresh_token_ciphertext='' THEN google_accounts.refresh_token_tag ELSE EXCLUDED.refresh_token_tag END, "
        "updated_at=NOW()",
        {google_sub, email, ciphertext, iv, tag});
    return result && PQresultStatus(result.get()) == PGRES_COMMAND_OK;
}

bool create_web_session(
    PGconn* connection,
    const std::string& google_sub,
    std::string& session_token,
    std::string& csrf_token) {
    if (!random_url_token(session_token) || !random_url_token(csrf_token)) return false;
    PgResult cleanup = execute_sql(connection, "DELETE FROM web_sessions WHERE expires_at <= NOW()");
    if (!cleanup || PQresultStatus(cleanup.get()) != PGRES_COMMAND_OK) return false;
    PgResult result = execute_sql(
        connection,
        "INSERT INTO web_sessions (session_hash,google_sub,csrf_hash,expires_at) "
        "VALUES ($1,$2,$3,NOW() + INTERVAL '30 days')",
        {sha256_hex(session_token), google_sub, sha256_hex(csrf_token)});
    return result && PQresultStatus(result.get()) == PGRES_COMMAND_OK;
}

bool create_access_token(PGconn* connection, const std::string& google_sub, std::string& access_token) {
    PgResult stored = execute_sql(
        connection,
        "SELECT refresh_token_ciphertext,refresh_token_iv,refresh_token_tag "
        "FROM google_accounts WHERE google_sub=$1",
        {google_sub});
    if (!stored || PQresultStatus(stored.get()) != PGRES_TUPLES_OK || PQntuples(stored.get()) != 1) {
        return false;
    }

    std::string refresh_token;
    if (!decrypt_secret(
            PQgetvalue(stored.get(), 0, 0),
            PQgetvalue(stored.get(), 0, 1),
            PQgetvalue(stored.get(), 0, 2),
            refresh_token)) {
        std::cerr << "無法解密 Google OAuth token；請確認 TOKEN_ENCRYPTION_KEY 與建立 token 時相同。" << std::endl;
        return false;
    }

    const std::string form = form_encode({
        {"client_id", environment_value("GOOGLE_CLIENT_ID")},
        {"client_secret", environment_value("GOOGLE_CLIENT_SECRET")},
        {"refresh_token", refresh_token},
        {"grant_type", "refresh_token"}
    });
    if (form.empty()) return false;
    const YouTubeResponse response = request_http(
        "https://oauth2.googleapis.com/token",
        "POST",
        form,
        {},
        "application/x-www-form-urlencoded");
    if (response.request_status != CURLE_OK || response.http_status < 200 || response.http_status >= 300) {
        const auto error = crow::json::load(response.body);
        const std::string error_code = error && error.t() == crow::json::type::Object
            ? read_json_string(error, "error") : std::string();
        std::cerr << "Google OAuth token refresh failed; HTTP " << response.http_status;
        if (!error_code.empty()) std::cerr << "; error=" << sanitize_api_error_detail(error_code, refresh_token);
        if (response.request_status != CURLE_OK) std::cerr << "; " << curl_easy_strerror(response.request_status);
        std::cerr << std::endl;
        return false;
    }
    const auto token_response = crow::json::load(response.body);
    if (!token_response || token_response.t() != crow::json::type::Object) return false;
    access_token = read_json_string(token_response, "access_token");
    if (access_token.empty()) return false;

    const std::string rotated_refresh_token = read_json_string(token_response, "refresh_token");
    if (!rotated_refresh_token.empty()) {
        std::string ciphertext;
        std::string iv;
        std::string tag;
        if (!encrypt_secret(rotated_refresh_token, ciphertext, iv, tag)) return false;
        PgResult update = execute_sql(
            connection,
            "UPDATE google_accounts SET refresh_token_ciphertext=$2,refresh_token_iv=$3,"
            "refresh_token_tag=$4,updated_at=NOW() WHERE google_sub=$1",
            {google_sub, ciphertext, iv, tag});
        if (!update || PQresultStatus(update.get()) != PGRES_COMMAND_OK) return false;
    }
    return true;
}

YouTubeResponse youtube_user_request(
    const std::string& access_token,
    const std::string& method,
    const std::string& endpoint,
    const std::vector<std::pair<std::string, std::string>>& parameters = {},
    const std::string& body = {}) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) return {CURLE_FAILED_INIT, 0, {}};
    std::string url = "https://www.googleapis.com/youtube/v3/" + endpoint;
    for (const auto& parameter : parameters) {
        const std::string name = url_encode(curl, parameter.first);
        const std::string value = url_encode(curl, parameter.second);
        if (name.empty() || value.empty()) {
            curl_easy_cleanup(curl);
            return {CURLE_URL_MALFORMAT, 0, {}};
        }
        url += (url.find('?') == std::string::npos ? '?' : '&');
        url += name + "=" + value;
    }
    curl_easy_cleanup(curl);
    return request_http(url, method, body, access_token, body.empty() ? std::string() : "application/json");
}

crow::response forward_user_youtube_response(const YouTubeResponse& result) {
    if (result.request_status != CURLE_OK) {
        std::cerr << "YouTube OAuth API request failed: " << curl_easy_strerror(result.request_status) << std::endl;
        return json_error(502, "無法連線至 YouTube，請稍後再試。");
    }
    if (result.http_status < 200 || result.http_status >= 300) {
        const YouTubeApiError details = parse_youtube_api_error(result.body);
        const std::string message = sanitize_api_error_detail(details.message, {});
        std::cerr << "YouTube OAuth API returned HTTP " << result.http_status;
        if (!details.reason.empty()) std::cerr << "; reason=" << sanitize_api_error_detail(details.reason, {});
        if (!details.status.empty()) std::cerr << "; status=" << sanitize_api_error_detail(details.status, {});
        if (!message.empty()) std::cerr << "; message=" << message;
        std::cerr << std::endl;
        return json_error(502, message.empty() ? "YouTube 操作失敗，請檢查授權或稍後再試。" : message);
    }
    if (result.body.empty()) {
        crow::response response("{\"ok\":true}");
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response.set_header("Cache-Control", "no-store");
        return response;
    }
    crow::response response(result.body);
    response.set_header("Content-Type", "application/json; charset=utf-8");
    response.set_header("Cache-Control", "no-store");
    return response;
}

bool prepare_user_api(
    const crow::request& request,
    PgConnection& database,
    AccountSession& session,
    std::string& access_token,
    crow::response& error) {
    if (!oauth_configuration_ready()) {
        error = json_error(503, "Google 登入尚未完成伺服器設定。");
        return false;
    }
    if (!database.connected() || !ensure_auth_schema(database.get())) {
        error = database_unavailable(database.get());
        return false;
    }
    if (!lookup_session(database.get(), request, session)) {
        error = authentication_required();
        return false;
    }
    if (!create_access_token(database.get(), session.google_sub, access_token)) {
        error = json_error(401, "Google 授權已失效，請重新登入並授權。");
        return false;
    }
    return true;
}

bool valid_playlist_id(const std::string& value) {
    static const std::regex pattern("^[a-zA-Z0-9_-]{1,128}$");
    return std::regex_match(value, pattern);
}

bool read_json_body(const crow::request& request, crow::json::rvalue& body) {
    if (request.body.size() > 16 * 1024) return false;
    body = crow::json::load(request.body);
    return body && body.t() == crow::json::type::Object;
}

std::string json_request_string(const crow::json::rvalue& body, const char* key) {
    return read_json_string(body, key);
}

const char* HOME_PAGE = R"html(<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>YouTube 影片探索</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; background: #0f0f0f; color: #f1f1f1; font: 14px Arial, sans-serif; }
    header { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; gap: 24px; height: 64px; padding: 0 24px; background: #0f0f0f; border-bottom: 1px solid #282828; }
    .brand { color: #f44; font-size: 20px; font-weight: bold; white-space: nowrap; }
    form { display: flex; width: min(600px, 70vw); margin: auto; }
    #account-button { flex: 0 0 auto; min-height: 40px; padding: 8px 14px; border-radius: 20px; }
    input { flex: 1; min-width: 0; padding: 11px 14px; color: #fff; background: #121212; border: 1px solid #303030; border-radius: 20px 0 0 20px; font-size: 16px; }
    button { color: #fff; background: #272727; border: 0; cursor: pointer; }
    form button { padding: 0 22px; border: 1px solid #303030; border-radius: 0 20px 20px 0; }
    .layout { display: grid; grid-template-columns: 210px minmax(0, 1fr); }
    nav { position: sticky; top: 64px; align-self: start; height: calc(100vh - 64px); padding: 18px 12px; border-right: 1px solid #282828; }
    nav button { width: 100%; margin-bottom: 8px; padding: 12px; text-align: left; border-radius: 9px; }
    nav button:hover, .video-card button:hover { background: #3a3a3a; }
    main { min-width: 0; max-width: 1500px; width: 100%; margin: 0 auto; padding: 22px 28px 50px; }
    h1 { margin: 0 0 18px; font-size: 22px; }
    #status { min-height: 20px; color: #aaa; }
    #categories { display: flex; gap: 10px; overflow-x: auto; padding: 2px 0 18px; }
    #categories button { flex: 0 0 auto; padding: 9px 14px; border-radius: 8px; }
    #categories button.active { color: #111; background: #f1f1f1; }
    .playlist-form { display: grid; width: 100%; max-width: 560px; gap: 10px; margin: 0 0 18px; }
    .playlist-form input, .playlist-form textarea, .playlist-form select { width: 100%; min-height: 42px; padding: 10px 12px; color: #fff; background: #181818; border: 1px solid #444; border-radius: 8px; font: inherit; }
    .playlist-form textarea { min-height: 80px; resize: vertical; }
    .playlist-form button, .playlist-card button { min-height: 40px; padding: 8px 14px; border-radius: 20px; }
    .playlist-card { margin: 0 0 16px; padding: 16px; border: 1px solid #303030; border-radius: 12px; }
    .playlist-card h2 { margin: 0 0 8px; font-size: 17px; }
    .playlist-card p { color: #aaa; }
    .playlist-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .playlist-items-form { display: flex; width: 100%; max-width: 560px; gap: 8px; margin: 0 0 20px; }
    .playlist-items-form input, .playlist-items-form select { flex: 1; min-width: 0; padding: 10px 12px; color: #fff; background: #181818; border: 1px solid #444; border-radius: 8px; font: inherit; }
    .playlist-items-form button { padding: 8px 14px; border-radius: 8px; }
    footer { margin-top: 36px; padding: 18px 0; border-top: 1px solid #282828; color: #aaa; font-size: 12px; line-height: 1.7; }
    footer a { margin-right: 14px; color: #ccc; }
    .authorization-notice { max-width: 650px; padding: 12px; border-left: 3px solid #f44; background: #181818; color: #ccc; line-height: 1.6; }
    #videos { display: grid; grid-template-columns: repeat(auto-fill, minmax(245px, 1fr)); gap: 28px 16px; }
    .video-card { display: flex; min-width: 0; flex-direction: column; }
    .video-card img { display: block; width: 100%; aspect-ratio: 16 / 9; object-fit: cover; border-radius: 12px; background: #222; }
    .video-card .thumbnail-button { position: relative; display: block; width: 100%; margin: 0; padding: 0; overflow: hidden; border-radius: 12px; background: transparent; }
    .video-card .thumbnail-button::after { content: "▶"; position: absolute; top: 50%; left: 50%; display: grid; width: 54px; height: 40px; transform: translate(-50%, -50%); place-items: center; border-radius: 10px; color: #fff; background: rgba(0, 0, 0, .72); font-size: 19px; pointer-events: none; }
    .video-card .thumbnail-button:hover { background: transparent; }
    .video-card .thumbnail-button:hover img { filter: brightness(.8); }
    .video-card .thumbnail-button:focus-visible { outline: 2px solid #f1f1f1; outline-offset: 3px; }
    .video-card h2 { display: -webkit-box; min-height: 2.8em; margin: 10px 0 6px; overflow: hidden; font-size: 16px; line-height: 1.4; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
    .video-card p { margin: 4px 0; color: #aaa; line-height: 1.45; }
    .video-card p:not(.description) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .video-card button { margin-top: 6px; padding: 8px 14px; border-radius: 18px; }
    .video-card .description { display: -webkit-box; min-height: 2.9em; overflow: hidden; white-space: normal; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
    .video-card .description.expanded { display: block; overflow: visible; white-space: pre-wrap; }
    .video-card .description-toggle { align-self: flex-start; min-height: 32px; margin-top: 0; padding: 4px 0; color: #aaa; background: transparent; border-radius: 0; text-align: left; }
    .video-card .description-toggle:hover { color: #fff; background: transparent; }
    .video-card .description-toggle[aria-hidden="true"] { visibility: hidden; }
    body.player-open { overflow: hidden; }
    #player-panel { position: fixed; inset: 0; z-index: 10; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; padding: 24px; background: rgba(0, 0, 0, .92); }
    #player-toolbar { display: flex; justify-content: flex-end; width: min(100%, 960px); }
    #player { width: min(100%, 960px); max-height: calc(100vh - 100px); aspect-ratio: 16 / 9; overflow: hidden; border-radius: 12px; background: #000; box-shadow: 0 16px 60px rgba(0, 0, 0, .5); }
    #player iframe { display: block; width: 100%; height: 100%; border: 0; }
    #close-player { padding: 9px 16px; border: 1px solid #555; border-radius: 20px; background: #272727; }
    #close-player:hover { background: #3a3a3a; }
    [hidden] { display: none !important; }
    @media (max-width: 700px) {
      header { height: auto; min-height: 0; flex-direction: row; flex-wrap: wrap; align-items: center; gap: 10px; padding: 12px 14px; }
      .brand { font-size: 18px; }
      header form { order: 2; width: 100%; margin: 0; }
      #account-button { margin-left: auto; }
      form button { min-height: 44px; padding: 0 18px; }
      input { min-height: 44px; }
      .layout { grid-template-columns: minmax(0, 1fr); }
      nav { position: sticky; top: 120px; z-index: 3; display: flex; height: auto; padding: 8px 12px; background: #0f0f0f; border-right: 0; border-bottom: 1px solid #282828; }
      nav button { width: auto; min-height: 44px; flex: 1; margin: 0; text-align: center; }
      main { padding: 18px 14px 36px; }
      h1 { margin-bottom: 14px; font-size: 20px; }
      #categories { gap: 8px; margin: 0 -14px; padding: 2px 14px 16px; scrollbar-width: thin; }
      #categories button { min-height: 40px; padding: 8px 13px; }
      #videos { grid-template-columns: minmax(0, 1fr); gap: 24px; }
      .video-card h2 { margin-top: 8px; font-size: 16px; }
      .video-card p { font-size: 13px; }
      .video-card button { min-height: 40px; }
      .video-card .description-toggle { min-height: 40px; }
      .playlist-form { max-width: none; }
      .playlist-items-form { max-width: none; }
      .playlist-items-form button { min-height: 44px; }
      #player-panel { gap: 8px; padding: max(12px, env(safe-area-inset-top)) 12px max(12px, env(safe-area-inset-bottom)); }
      #player-toolbar { width: 100%; }
      #player { width: 100%; max-height: calc(100vh - 88px); border-radius: 8px; }
      #close-player { min-height: 44px; }
    }
    @media (max-width: 380px) {
      header { padding-right: 10px; padding-left: 10px; }
      main { padding-right: 10px; padding-left: 10px; }
      #categories { margin-right: -10px; margin-left: -10px; padding-right: 10px; padding-left: 10px; }
      #player-panel { padding-right: 8px; padding-left: 8px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">YouTube 探索</div>
    <button id="account-button" type="button" disabled>登入 Google</button>
    <form id="search-form" role="search">
      <input id="query" type="search" maxlength="200" placeholder="搜尋影片" aria-label="搜尋影片" required>
      <button type="submit">搜尋</button>
    </form>
  </header>
  <div class="layout">
    <nav aria-label="主要導覽">
      <button type="button" data-view="popular">首頁 / 熱門</button>
      <button type="button" data-view="search">搜尋結果</button>
      <button type="button" data-view="playlists">我的清單</button>
    </nav>
    <main>
      <section id="player-panel" role="dialog" aria-modal="true" aria-label="影片播放器" hidden>
        <div id="player-toolbar">
          <button id="close-player" type="button">關閉播放器</button>
        </div>
        <div id="player"></div>
      </section>
      <h1 id="heading">熱門影片</h1>
      <div id="categories" aria-label="影片分類"></div>
      <p id="status" role="status"></p>
      <section id="videos" aria-live="polite"></section>
      <footer>
        YouTube 影片與播放清單屬於各自權利人；本服務透過 YouTube API 和官方播放器提供功能，並非 YouTube 官方產品。
        <div><a href="/privacy">隱私權政策</a><a href="/terms">使用條款與版權聲明</a></div>
      </footer>
    </main>
  </div>
  <script>
    const searchForm = document.getElementById('search-form');
    const queryInput = document.getElementById('query');
    const heading = document.getElementById('heading');
    const status = document.getElementById('status');
    const videos = document.getElementById('videos');
    const categories = document.getElementById('categories');
    const playerPanel = document.getElementById('player-panel');
    const closePlayer = document.getElementById('close-player');
    const accountButton = document.getElementById('account-button');
    let player = null;
    let playerReady = false;
    let pendingVideoId = null;
    let playerTrigger = null;
    let authenticated = false;
    let csrfToken = '';

    function closeVideoPlayer() {
      pendingVideoId = null;
      playerPanel.hidden = true;
      document.body.classList.remove('player-open');
      if (playerReady && player) player.stopVideo();
      if (playerTrigger && playerTrigger.isConnected) playerTrigger.focus();
      playerTrigger = null;
    }

    playerPanel.addEventListener('click', event => {
      if (event.target === playerPanel) closeVideoPlayer();
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !playerPanel.hidden) closeVideoPlayer();
    });
    function formatDuration(value) {
      const match = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(value || '');
      if (!match) return '';
      const hours = Number(match[1] || 0);
      const minutes = Number(match[2] || 0);
      const seconds = Number(match[3] || 0);
      const parts = hours
        ? [hours, String(minutes).padStart(2, '0'), String(seconds).padStart(2, '0')]
        : [minutes, String(seconds).padStart(2, '0')];
      return parts.join(':');
    }

    closePlayer.addEventListener('click', closeVideoPlayer);

    window.onYouTubeIframeAPIReady = () => {
      player = new YT.Player('player', {
        width: '100%',
        videoId: '',
        playerVars: { playsinline: 1, rel: 0, origin: window.location.origin },
        events: {
          onReady: () => {
            playerReady = true;
            if (pendingVideoId) player.loadVideoById(pendingVideoId);
          }
        }
      });
    };

    function playVideo(videoId, trigger) {
      if (!/^[a-zA-Z0-9_-]{11}$/.test(videoId)) return;
      playerTrigger = trigger;
      playerPanel.hidden = false;
      document.body.classList.add('player-open');
      pendingVideoId = videoId;
      if (playerReady && player) player.loadVideoById(videoId);
      closePlayer.focus();
    }

    function displayVideos(items) {
      videos.replaceChildren();
      for (const item of items || []) {
        const videoId = typeof item.id === 'string' ? item.id : item.id && item.id.videoId;
        const snippet = item.snippet;
        if (!videoId || !snippet) continue;

        const card = document.createElement('article');
        card.className = 'video-card';
        const thumbnailButton = document.createElement('button');
        thumbnailButton.type = 'button';
        thumbnailButton.className = 'thumbnail-button';
        thumbnailButton.setAttribute('aria-label', '播放影片：' + (snippet.title || '未命名影片'));
        thumbnailButton.addEventListener('click', event => playVideo(videoId, event.currentTarget));
        const thumbnail = document.createElement('img');
        const thumbnails = snippet.thumbnails || {};
        thumbnail.src = (thumbnails.medium && thumbnails.medium.url) ||
          (thumbnails.high && thumbnails.high.url) ||
          (thumbnails.default && thumbnails.default.url) || '';
        thumbnail.alt = '';
        thumbnail.loading = 'lazy';
        thumbnailButton.append(thumbnail);

        const title = document.createElement('h2');
        title.textContent = snippet.title || '未命名影片';
        const channel = document.createElement('p');
        const duration = formatDuration(item.contentDetails && item.contentDetails.duration);
        channel.textContent = [snippet.channelTitle, duration].filter(Boolean).join(' · ');
        const description = document.createElement('p');
        description.className = 'description';
        description.id = 'video-description-' + videoId;
        description.textContent = snippet.description || '沒有提供影片說明。';
        const descriptionToggle = document.createElement('button');
        descriptionToggle.type = 'button';
        descriptionToggle.className = 'description-toggle';
        descriptionToggle.textContent = '顯示更多';
        descriptionToggle.setAttribute('aria-controls', description.id);
        descriptionToggle.setAttribute('aria-expanded', 'false');
        descriptionToggle.disabled = true;
        descriptionToggle.setAttribute('aria-hidden', 'true');
        descriptionToggle.addEventListener('click', () => {
          const expanded = descriptionToggle.getAttribute('aria-expanded') !== 'true';
          description.classList.toggle('expanded', expanded);
          descriptionToggle.setAttribute('aria-expanded', String(expanded));
          descriptionToggle.textContent = expanded ? '收合' : '顯示更多';
        });
        const playButton = document.createElement('button');
        playButton.type = 'button';
        playButton.textContent = '播放';
        playButton.addEventListener('click', event => playVideo(videoId, event.currentTarget));

        card.append(thumbnailButton, title, channel, description, descriptionToggle, playButton);
        const addButton = document.createElement('button');
        addButton.type = 'button';
        addButton.className = 'add-playlist-button';
        addButton.textContent = authenticated ? '加入播放清單' : '登入後加入播放清單';
        addButton.addEventListener('click', async () => {
          if (!authenticated) {
            if (accountButton.disabled) status.textContent = 'Google 登入尚未完成伺服器設定。';
            else window.location.href = '/auth/google';
            return;
          }
          if (card.querySelector('.playlist-items-form')) return;
          addButton.disabled = true;
          try {
            const playlistData = await playlistApi('/api/my/playlists');
            const playlists = playlistData.items || [];
            if (!playlists.length) {
              status.textContent = '請先到「我的清單」建立播放清單。';
              return;
            }
            const form = document.createElement('form');
            form.className = 'playlist-items-form';
            const select = document.createElement('select');
            select.setAttribute('aria-label', '選擇播放清單');
            for (const playlist of playlists) {
              if (!playlist.id || !playlist.snippet) continue;
              const option = document.createElement('option');
              option.value = playlist.id;
              option.textContent = playlist.snippet.title || '未命名播放清單';
              select.append(option);
            }
            const confirmButton = document.createElement('button');
            confirmButton.type = 'submit';
            confirmButton.textContent = '加入';
            form.append(select, confirmButton);
            form.addEventListener('submit', async event => {
              event.preventDefault();
              confirmButton.disabled = true;
              try {
                await playlistApi('/api/my/playlist-items', {
                  method: 'POST',
                  body: JSON.stringify({ playlistId: select.value, videoId })
                });
                status.textContent = '影片已加入播放清單。';
                form.remove();
              } catch (error) {
                status.textContent = error.message || '無法加入播放清單。';
              } finally {
                confirmButton.disabled = false;
              }
            });
            card.append(form);
          } catch (error) {
            status.textContent = error.message || '無法載入播放清單。';
          } finally {
            addButton.disabled = false;
          }
        });
        card.append(addButton);
        videos.append(card);
        const hasLongDescription = description.scrollHeight > description.clientHeight + 1;
        descriptionToggle.disabled = !hasLongDescription;
        descriptionToggle.setAttribute('aria-hidden', String(!hasLongDescription));
      }
      if (!videos.children.length) status.textContent = '找不到符合的影片。';
      else status.textContent = '';
    }

    async function playlistApi(url, options = {}) {
      const headers = new Headers(options.headers || {});
      if (options.method && options.method !== 'GET' && csrfToken) {
        headers.set('X-CSRF-Token', csrfToken);
      }
      if (options.body) headers.set('Content-Type', 'application/json');
      const response = await fetch(url, { ...options, headers });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '播放清單操作失敗。');
      return data;
    }

    function makeButton(label, action) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.addEventListener('click', action);
      return button;
    }

    async function updateAccountStatus() {
      try {
        const response = await fetch('/api/auth/status');
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || '無法確認登入狀態。');
        authenticated = data.authenticated === true;
        csrfToken = data.csrfToken || '';
        accountButton.disabled = data.configured !== true;
        accountButton.textContent = data.configured !== true
          ? '登入未設定'
          : authenticated ? '登出' : '登入 Google';
        document.querySelectorAll('.add-playlist-button').forEach(button => {
          button.textContent = authenticated ? '加入播放清單' : '登入後加入播放清單';
        });
      } catch (error) {
        accountButton.disabled = true;
        accountButton.textContent = '登入狀態無法載入';
        status.textContent = error.message || '無法確認登入狀態。';
      }
    }

    function appendPlaylistForm(parent, initial = {}) {
      const form = document.createElement('form');
      form.className = 'playlist-form';
      const titleInput = document.createElement('input');
      titleInput.required = true;
      titleInput.maxLength = 150;
      titleInput.placeholder = '播放清單名稱';
      titleInput.setAttribute('aria-label', '播放清單名稱');
      titleInput.value = initial.title || '';
      const descriptionInput = document.createElement('textarea');
      descriptionInput.maxLength = 5000;
      descriptionInput.placeholder = '描述（選填）';
      descriptionInput.setAttribute('aria-label', '播放清單描述');
      descriptionInput.value = initial.description || '';
      const privacySelect = document.createElement('select');
      privacySelect.setAttribute('aria-label', '播放清單隱私');
      for (const [value, label] of [['private', '私人'], ['unlisted', '不公開'], ['public', '公開']]) {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = label;
        privacySelect.append(option);
      }
      privacySelect.value = initial.privacyStatus || 'private';
      const submit = document.createElement('button');
      submit.type = 'submit';
      submit.textContent = initial.playlistId ? '儲存變更' : '建立播放清單';
      form.append(titleInput, descriptionInput, privacySelect, submit);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        submit.disabled = true;
        try {
          await playlistApi('/api/my/playlists', {
            method: initial.playlistId ? 'PUT' : 'POST',
            body: JSON.stringify({
              playlistId: initial.playlistId,
              title: titleInput.value.trim(),
              description: descriptionInput.value.trim(),
              privacyStatus: privacySelect.value
            })
          });
          status.textContent = initial.playlistId ? '播放清單已更新。' : '播放清單已建立。';
          await loadMyPlaylists();
        } catch (error) {
          status.textContent = error.message || '播放清單操作失敗。';
        } finally {
          submit.disabled = false;
        }
      });
      parent.append(form);
    }

    async function loadMyPlaylists(pageToken = '') {
      heading.textContent = '我的 YouTube 播放清單';
      categories.replaceChildren();
      videos.replaceChildren();
      status.textContent = '';
      closeVideoPlayer();
      if (!authenticated) {
        status.textContent = '登入並授權 YouTube 後，即可管理自己的播放清單。';
        const notice = document.createElement('p');
        notice.className = 'authorization-notice';
        notice.textContent = '登入只用來識別 Google 帳戶。若繼續，你會另外授權本服務管理 YouTube 播放清單（包括建立、修改及刪除）。網站不會取得你的 Google 密碼；授權資料會加密保存，你可以隨時解除連結並撤銷授權。';
        videos.append(notice);
        videos.append(makeButton('使用 Google 登入', () => { window.location.href = '/auth/google'; }));
        return;
      }

      appendPlaylistForm(videos);
      videos.append(makeButton('解除 Google 授權', async () => {
        if (!window.confirm('解除後，網站將刪除保存的授權資料並停止管理你的 YouTube 清單。確定繼續？')) return;
        try {
          await playlistApi('/api/auth/disconnect', { method: 'POST' });
          authenticated = false;
          csrfToken = '';
          await updateAccountStatus();
          await loadMyPlaylists();
        } catch (error) {
          status.textContent = error.message || '無法解除 Google 授權。';
        }
      }));
      try {
        const url = '/api/my/playlists' + (pageToken ? '?pageToken=' + encodeURIComponent(pageToken) : '');
        const data = await playlistApi(url);
        if (pageToken) {
          videos.append(makeButton('回到清單第一頁', () => loadMyPlaylists()));
        }
        const items = data.items || [];
        for (const item of items) {
          if (!item.id || !item.snippet) continue;
          const card = document.createElement('article');
          card.className = 'playlist-card';
          const title = document.createElement('h2');
          title.textContent = item.snippet.title || '未命名播放清單';
          const description = document.createElement('p');
          description.textContent = item.snippet.description || '';
          const metadata = document.createElement('p');
          metadata.textContent = (item.contentDetails && item.contentDetails.itemCount || 0) +
            ' 部影片 · ' + (item.status && item.status.privacyStatus || 'private');
          const actions = document.createElement('div');
          actions.className = 'playlist-actions';
          actions.append(
            makeButton('查看影片', () => loadPlaylistItems(item.id, title.textContent)),
            makeButton('編輯', () => {
              if (card.querySelector('.playlist-form')) return;
              appendPlaylistForm(card, {
                playlistId: item.id,
                title: item.snippet.title,
                description: item.snippet.description,
                privacyStatus: item.status && item.status.privacyStatus
              });
            }),
            makeButton('刪除', async () => {
              if (!window.confirm('確定刪除播放清單「' + title.textContent + '」？此操作會直接刪除 YouTube 上的清單。')) return;
              try {
                await playlistApi('/api/my/playlists?id=' + encodeURIComponent(item.id), { method: 'DELETE' });
                status.textContent = '播放清單已刪除。';
                await loadMyPlaylists();
              } catch (error) {
                status.textContent = error.message || '無法刪除播放清單。';
              }
            })
          );
          card.append(title, description, metadata, actions);
          videos.append(card);
        }
        if (!items.length) status.textContent = '目前沒有播放清單，可以先建立一份。';
        if (data.nextPageToken) {
          videos.append(makeButton('載入更多播放清單', () => loadMyPlaylists(data.nextPageToken)));
        }
      } catch (error) {
        status.textContent = error.message || '無法載入播放清單。';
      }
    }

    async function loadPlaylistItems(playlistId, playlistTitle, pageToken = '') {
      heading.textContent = playlistTitle;
      categories.replaceChildren(
        makeButton('返回我的清單', () => loadMyPlaylists()),
        ...(pageToken ? [makeButton('回到影片第一頁', () => loadPlaylistItems(playlistId, playlistTitle))] : [])
      );
      videos.replaceChildren();
      status.textContent = '載入播放清單…';
      const addForm = document.createElement('form');
      addForm.className = 'playlist-items-form';
      const videoIdInput = document.createElement('input');
      videoIdInput.placeholder = 'YouTube 影片 ID（11 個字元）';
      videoIdInput.maxLength = 11;
      videoIdInput.required = true;
      videoIdInput.setAttribute('aria-label', 'YouTube 影片 ID');
      const addButton = document.createElement('button');
      addButton.type = 'submit';
      addButton.textContent = '新增影片';
      addForm.append(videoIdInput, addButton);
      addForm.addEventListener('submit', async event => {
        event.preventDefault();
        try {
          await playlistApi('/api/my/playlist-items', {
            method: 'POST',
            body: JSON.stringify({ playlistId, videoId: videoIdInput.value.trim() })
          });
          videoIdInput.value = '';
          await loadPlaylistItems(playlistId, playlistTitle);
        } catch (error) {
          status.textContent = error.message || '無法新增影片。';
        }
      });
      videos.append(addForm);

      try {
        const url = '/api/my/playlist-items?playlistId=' + encodeURIComponent(playlistId) +
          (pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : '');
        const data = await playlistApi(url);
        for (const item of data.items || []) {
          const videoId = item.snippet && item.snippet.resourceId && item.snippet.resourceId.videoId;
          if (!videoId || !item.id) continue;
          const card = document.createElement('article');
          card.className = 'playlist-card';
          const title = document.createElement('h2');
          title.textContent = item.snippet.title || '未命名影片';
          const channel = document.createElement('p');
          channel.textContent = item.snippet.videoOwnerChannelTitle || '';
          const actions = document.createElement('div');
          actions.className = 'playlist-actions';
          actions.append(
            makeButton('播放', event => playVideo(videoId, event.currentTarget)),
            makeButton('從清單移除', async () => {
              if (!window.confirm('確定從播放清單移除此影片？')) return;
              try {
                await playlistApi(
                  '/api/my/playlist-items?playlistId=' + encodeURIComponent(playlistId) +
                    '&itemId=' + encodeURIComponent(item.id),
                  { method: 'DELETE' });
                await loadPlaylistItems(playlistId, playlistTitle);
              } catch (error) {
                status.textContent = error.message || '無法移除影片。';
              }
            })
          );
          card.append(title, channel, actions);
          videos.append(card);
        }
        status.textContent = data.items && data.items.length ? '' : '此播放清單目前沒有影片。';
        if (data.nextPageToken) {
          videos.append(makeButton('載入更多影片', () => loadPlaylistItems(playlistId, playlistTitle, data.nextPageToken)));
        }
      } catch (error) {
        status.textContent = error.message || '無法載入清單影片。';
      }
    }

    async function loadVideoList(url, title) {
      heading.textContent = title;
      status.textContent = '載入中…';
      videos.replaceChildren();
      try {
        const response = await fetch(url);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || '無法載入影片，請稍後再試。');
        let items = data.items || [];
        if (url.startsWith('/api/search') && items.length) {
          const ids = items.map(item => item.id && item.id.videoId).filter(Boolean);
          const detailResponse = await fetch('/api/details?ids=' + encodeURIComponent(ids.join(',')));
          const detailData = await detailResponse.json();
          if (!detailResponse.ok) throw new Error(detailData.error || '無法載入影片詳細資料。');
          const detailsById = new Map((detailData.items || []).map(item => [item.id, item.contentDetails]));
          items = items.map(item => ({
            ...item,
            contentDetails: detailsById.get(item.id && item.id.videoId)
          }));
        }
        displayVideos(items);
      } catch (error) {
        status.textContent = error.message || '無法載入影片，請稍後再試。';
      }
    }

    async function loadCategories() {
      try {
        const response = await fetch('/api/categories');
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || '無法載入影片分類。');

        const allButton = document.createElement('button');
        allButton.type = 'button';
        allButton.textContent = '全部';
        allButton.className = 'active';
        allButton.addEventListener('click', () => {
          categories.querySelectorAll('button').forEach(button => button.classList.remove('active'));
          allButton.classList.add('active');
          loadVideoList('/api/popular', '熱門影片');
        });
        categories.append(allButton);

        for (const item of data.items || []) {
          if (!item.id || !item.snippet || item.snippet.assignable === false) continue;
          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = item.snippet.title || '影片分類';
          button.addEventListener('click', () => {
            categories.querySelectorAll('button').forEach(category => category.classList.remove('active'));
            button.classList.add('active');
            loadVideoList('/api/popular?categoryId=' + encodeURIComponent(item.id), button.textContent);
          });
          categories.append(button);
        }
      } catch (error) {
        status.textContent = error.message || '無法載入影片分類。';
      }
    }

    searchForm.addEventListener('submit', async event => {
      event.preventDefault();
      const query = queryInput.value.trim();
      if (!query) return;
      closeVideoPlayer();
      categories.replaceChildren();
      await loadVideoList('/api/search?q=' + encodeURIComponent(query), '搜尋結果');
    });

    document.querySelector('[data-view="popular"]').addEventListener('click', () => {
      closeVideoPlayer();
      categories.querySelectorAll('button').forEach(button => button.classList.remove('active'));
      const allButton = categories.querySelector('button');
      if (allButton) allButton.classList.add('active');
      loadVideoList('/api/popular', '熱門影片');
    });

    document.querySelector('[data-view="search"]').addEventListener('click', () => {
      queryInput.focus();
    });

    document.querySelector('[data-view="playlists"]').addEventListener('click', () => loadMyPlaylists());
    accountButton.addEventListener('click', async () => {
      if (!authenticated) {
        window.location.href = '/auth/google';
        return;
      }
      try {
        await playlistApi('/api/auth/logout', { method: 'POST' });
        authenticated = false;
        csrfToken = '';
        status.textContent = '已登出 Google 帳戶。';
        await updateAccountStatus();
        document.querySelector('[data-view="popular"]').click();
      } catch (error) {
        status.textContent = error.message || '登出失敗。';
      }
    });

    const iframeApi = document.createElement('script');
    iframeApi.src = 'https://www.youtube.com/iframe_api';
    document.head.append(iframeApi);

    loadCategories();
    loadVideoList('/api/popular', '熱門影片');
    updateAccountStatus();
  </script>
</body>
</html>)html";

const char* PRIVACY_PAGE = R"html(<!doctype html>
<html lang="zh-Hant"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>隱私權政策｜YouTube 影片探索</title>
<style>body{max-width:760px;margin:0 auto;padding:24px;color:#f1f1f1;background:#0f0f0f;font:16px/1.7 Arial,sans-serif}a{color:#9cf}h1,h2{line-height:1.3}li{margin:8px 0}</style></head>
<body><p><a href="/">返回首頁</a></p><h1>隱私權政策</h1><p>更新日期：2026 年 10 月 23 日</p>
<p>本服務提供 YouTube 影片搜尋、播放及 YouTube 播放清單管理功能。使用 Google 登入是自願的；不登入仍可使用公開影片探索功能。</p>
<h2>我們存取及保存的資料</h2><ul>
<li>Google 帳戶識別碼及電子郵件，用於識別登入帳戶。</li>
<li>你授權的 OAuth refresh token，以 AES-256-GCM 加密後保存於 Render Postgres；短效 access token 僅在伺服器記憶體中用於 API 請求。</li>
<li>登入 session 與 CSRF 防護資料；session 最長 30 天。</li>
<li>播放清單和影片資料由 YouTube 提供，供本服務即時顯示與操作；本服務不以自有資料庫作為播放清單的主要儲存位置。</li></ul>
<h2>資料使用與第三方服務</h2><p>資料只用於登入、維持授權，以及依照你的操作透過 YouTube Data API 讀取或管理你的播放清單。Google 會依其政策處理 API 請求；Render 提供本服務主機及資料庫。本站不會索取或保存你的 Google 密碼，也不會出售你的 Google 使用者資料。</p>
<h2>撤銷與刪除</h2><p>使用「我的清單」中的「解除 Google 授權」，本服務會向 Google 撤銷授權，並刪除本站保存的帳戶 token 與登入 session。你也可以在 Google 帳戶的第三方連結設定中撤銷授權；撤銷後，可能需要回到本站清除已保存的連結資料。播放清單的建立或刪除會直接影響你的 YouTube 帳戶。</p>
<h2>安全與聯絡</h2><p>本站使用 HTTPS cookie、CSRF 防護、參數化資料庫查詢及加密 token 儲存。任何網路服務都不能保證絕對安全。隱私或資料刪除問題，請聯絡本網站營運者。</p>
<p>本服務使用 YouTube API Services，使用即受 <a href="https://www.youtube.com/t/terms">YouTube 服務條款</a>及 <a href="https://policies.google.com/privacy">Google 隱私權政策</a>約束。</p>
</body></html>)html";

const char* TERMS_PAGE = R"html(<!doctype html>
<html lang="zh-Hant"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>使用條款與版權聲明｜YouTube 影片探索</title>
<style>body{max-width:760px;margin:0 auto;padding:24px;color:#f1f1f1;background:#0f0f0f;font:16px/1.7 Arial,sans-serif}a{color:#9cf}h1,h2{line-height:1.3}</style></head>
<body><p><a href="/">返回首頁</a></p><h1>使用條款與版權聲明</h1><p>更新日期：2026 年 10 月 23 日</p>
<p>本服務是獨立的第三方應用程式，並非 YouTube 或 Google 官方產品。YouTube 名稱、標誌、影片、縮圖及相關內容的權利屬於各自權利人；本服務不主張擁有這些內容。</p>
<p>影片與播放清單透過 YouTube API 和 YouTube 官方播放器呈現，並受 <a href="https://www.youtube.com/t/terms">YouTube 服務條款</a>及 <a href="https://developers.google.com/youtube/terms/developer-policies">YouTube API 服務政策</a>約束。本服務不提供影片下載或繞過 YouTube 播放器限制的功能。</p>
<p>連結 Google 帳戶後，你授權本服務依照你明確的操作，讀取、建立、修改或刪除該帳戶的 YouTube 播放清單及清單項目。刪除操作會直接影響 YouTube 帳戶，送出前請確認目標清單或影片。</p>
<p>你必須有權管理所選帳戶與內容，並遵守適用法律及第三方服務條款。本服務依現況提供；YouTube API、Google 授權、網路或配額變更可能影響功能可用性。</p>
<p>隱私及授權資料處理方式請參閱 <a href="/privacy">隱私權政策</a>。Google 帳戶授權可隨時在本站或 Google 帳戶設定中撤銷。</p>
</body></html>)html";

}  // namespace

int main() {
    const CURLcode curl_status = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_status != CURLE_OK) {
        std::cerr << "無法初始化 HTTP 用戶端：" << curl_easy_strerror(curl_status) << std::endl;
        return 1;
    }

    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);

    CROW_ROUTE(app, "/")([] {
        crow::response response(HOME_PAGE);
        response.set_header("Content-Type", "text/html; charset=utf-8");
        response.set_header("Cache-Control", "no-store");
        response.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
        return response;
    });

    CROW_ROUTE(app, "/privacy")([] {
        crow::response response(PRIVACY_PAGE);
        response.set_header("Content-Type", "text/html; charset=utf-8");
        response.set_header("Referrer-Policy", "no-referrer");
        return response;
    });

    CROW_ROUTE(app, "/terms")([] {
        crow::response response(TERMS_PAGE);
        response.set_header("Content-Type", "text/html; charset=utf-8");
        response.set_header("Referrer-Policy", "no-referrer");
        return response;
    });

    CROW_ROUTE(app, "/auth/google").methods(crow::HTTPMethod::GET)([] {
        const auto configuration_issues = oauth_configuration_issues();
        if (!configuration_issues.empty()) {
            log_oauth_configuration_issues(configuration_issues);
            return json_error(503, "Google OAuth、Postgres 或 TOKEN_ENCRYPTION_KEY 尚未設定。");
        }
        PgConnection database;
        if (!database.connected() || !ensure_auth_schema(database.get())) return database_unavailable(database.get());

        std::string state;
        if (!random_url_token(state) || !create_oauth_state(database.get(), state)) {
            return json_error(500, "無法開始 Google 登入，請稍後再試。");
        }
        CURL* curl = curl_easy_init();
        if (curl == nullptr) return json_error(500, "無法開始 Google 登入，請稍後再試。");
        const std::string authorization_url =
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=" +
            url_encode(curl, environment_value("GOOGLE_CLIENT_ID")) +
            "&redirect_uri=" + url_encode(curl, environment_value("GOOGLE_REDIRECT_URI")) +
            "&scope=" + url_encode(curl,
                "openid email profile https://www.googleapis.com/auth/youtube.force-ssl") +
            "&access_type=offline&include_granted_scopes=true&prompt=consent&state=" +
            url_encode(curl, state);
        curl_easy_cleanup(curl);

        crow::response response(302);
        response.set_header("Location", authorization_url);
        response.set_header("Cache-Control", "no-store");
        response.set_header("Referrer-Policy", "no-referrer");
        response.set_header(
            "Set-Cookie",
            "oauth_state=" + state + "; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax");
        return response;
    });

    CROW_ROUTE(app, "/auth/callback").methods(crow::HTTPMethod::GET)([](const crow::request& request) {
        const auto configuration_issues = oauth_configuration_issues();
        if (!configuration_issues.empty()) {
            log_oauth_configuration_issues(configuration_issues);
            return json_error(503, "Google OAuth 尚未完成伺服器設定。");
        }
        PgConnection database;
        if (!database.connected() || !ensure_auth_schema(database.get())) return database_unavailable(database.get());

        const std::string state = request.url_params.get("state") == nullptr
            ? std::string() : std::string(request.url_params.get("state"));
        const std::string state_cookie = cookie_value(request, "oauth_state");
        if (state.empty() || state_cookie.size() != state.size() ||
            CRYPTO_memcmp(state.data(), state_cookie.data(), state.size()) != 0 ||
            !consume_oauth_state(database.get(), state)) {
            return json_error(400, "Google 登入驗證已失效，請重新登入。");
        }
        const char* oauth_error = request.url_params.get("error");
        if (oauth_error != nullptr) {
            std::cerr << "Google OAuth authorization was not completed: "
                      << sanitize_api_error_detail(oauth_error, {}) << std::endl;
            return json_error(400, "你尚未完成 Google／YouTube 授權。");
        }
        const char* code = request.url_params.get("code");
        if (code == nullptr || *code == '\0' || std::string(code).size() > 4096) {
            return json_error(400, "Google 登入回應缺少授權碼，請重試。");
        }

        const YouTubeResponse token_response = exchange_oauth_code(code);
        const auto token_data = crow::json::load(token_response.body);
        if (token_response.request_status != CURLE_OK || token_response.http_status < 200 ||
            token_response.http_status >= 300 || !token_data ||
            token_data.t() != crow::json::type::Object) {
            std::cerr << "Google OAuth code exchange failed; HTTP " << token_response.http_status << std::endl;
            return json_error(502, "Google 授權交換失敗，請確認 OAuth 設定後重試。");
        }

        const std::string access_token = read_json_string(token_data, "access_token");
        const std::string refresh_token = read_json_string(token_data, "refresh_token");
        const std::string granted_scopes = read_json_string(token_data, "scope");
        if (access_token.empty()) {
            return json_error(502, "Google 沒有回傳有效的登入 token，請重試。");
        }
        if (granted_scopes.find("https://www.googleapis.com/auth/youtube.force-ssl") == std::string::npos) {
            return json_error(403, "你尚未授予管理 YouTube 播放清單所需的權限。");
        }
        std::string google_sub;
        std::string email;
        if (!fetch_google_identity(access_token, google_sub, email)) {
            return json_error(502, "無法確認 Google 帳戶資訊，請稍後重試。");
        }
        if (!save_google_account(database.get(), google_sub, email, refresh_token)) {
            return json_error(502, "無法安全保存授權資料，請重新登入並同意離線存取。");
        }

        std::string session_token;
        std::string csrf_token;
        if (!create_web_session(database.get(), google_sub, session_token, csrf_token)) {
            return json_error(500, "無法建立登入工作階段，請稍後再試。");
        }
        crow::response response(302);
        response.set_header("Location", "/");
        response.set_header("Cache-Control", "no-store");
        response.set_header("Referrer-Policy", "no-referrer");
        response.set_header(
            "Set-Cookie",
            "app_session=" + session_token + "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax");
        response.add_header(
            "Set-Cookie",
            "csrf_token=" + csrf_token + "; Path=/; Max-Age=2592000; Secure; SameSite=Strict");
        return response;
    });

    CROW_ROUTE(app, "/api/auth/status").methods(crow::HTTPMethod::GET)([](const crow::request& request) {
        crow::json::wvalue body;
        const auto configuration_issues = oauth_configuration_issues();
        body["configured"] = configuration_issues.empty();
        body["authenticated"] = false;
        if (!configuration_issues.empty()) {
            log_oauth_configuration_issues(configuration_issues);
            std::string message;
            for (const auto& issue : configuration_issues) {
                if (!message.empty()) message += " ";
                message += issue;
            }
            body["configurationError"] = message;
            crow::response response(body.dump());
            response.set_header("Content-Type", "application/json; charset=utf-8");
            response.set_header("Cache-Control", "no-store");
            return response;
        }

        PgConnection database;
        if (!database.connected() || !ensure_auth_schema(database.get())) return database_unavailable(database.get());
        AccountSession session;
        if (lookup_session(database.get(), request, session)) {
            body["authenticated"] = true;
            body["email"] = session.email;
            const std::string csrf_token = cookie_value(request, "csrf_token");
            if (!csrf_token.empty() && sha256_hex(csrf_token) == session.csrf_hash) {
                body["csrfToken"] = csrf_token;
            }
        }
        crow::response response(body.dump());
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response.set_header("Cache-Control", "no-store");
        return response;
    });

    CROW_ROUTE(app, "/api/auth/logout").methods(crow::HTTPMethod::POST)([](const crow::request& request) {
        PgConnection database;
        if (!database.connected() || !ensure_auth_schema(database.get())) return database_unavailable(database.get());
        AccountSession session;
        if (!lookup_session(database.get(), request, session)) return authentication_required();
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");

        PgResult deleted = execute_sql(
            database.get(),
            "DELETE FROM web_sessions WHERE session_hash=$1",
            {sha256_hex(cookie_value(request, "app_session"))});
        if (!deleted || PQresultStatus(deleted.get()) != PGRES_COMMAND_OK) return database_unavailable(database.get());
        crow::response response("{\"ok\":true}");
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response.set_header("Cache-Control", "no-store");
        response.add_header("Set-Cookie", "app_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
        response.add_header("Set-Cookie", "csrf_token=; Path=/; Max-Age=0; Secure; SameSite=Strict");
        return response;
    });

    CROW_ROUTE(app, "/api/auth/disconnect").methods(crow::HTTPMethod::POST)([](const crow::request& request) {
        if (!oauth_configuration_ready()) return json_error(503, "Google OAuth 尚未完成伺服器設定。");
        PgConnection database;
        if (!database.connected() || !ensure_auth_schema(database.get())) return database_unavailable(database.get());
        AccountSession session;
        if (!lookup_session(database.get(), request, session)) return authentication_required();
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");

        PgResult stored = execute_sql(
            database.get(),
            "SELECT refresh_token_ciphertext,refresh_token_iv,refresh_token_tag "
            "FROM google_accounts WHERE google_sub=$1",
            {session.google_sub});
        std::string refresh_token;
        if (!stored || PQresultStatus(stored.get()) != PGRES_TUPLES_OK ||
            PQntuples(stored.get()) != 1 ||
            !decrypt_secret(
                PQgetvalue(stored.get(), 0, 0),
                PQgetvalue(stored.get(), 0, 1),
                PQgetvalue(stored.get(), 0, 2),
                refresh_token)) {
            return json_error(500, "無法讀取授權資料；帳戶連結尚未解除。");
        }
        const std::string form = form_encode({{"token", refresh_token}});
        if (form.empty()) return json_error(500, "無法建立 Google 撤銷請求；帳戶連結尚未解除。");
        const YouTubeResponse revoke_response = request_http(
            "https://oauth2.googleapis.com/revoke",
            "POST",
            form,
            {},
            "application/x-www-form-urlencoded");
        if (revoke_response.request_status != CURLE_OK ||
            (revoke_response.http_status != 200 && revoke_response.http_status != 400)) {
            std::cerr << "Google OAuth revoke request failed; HTTP " << revoke_response.http_status << std::endl;
            return json_error(502, "Google 尚未確認撤銷授權；帳戶連結仍保留，請稍後重試。");
        }
        PgResult deleted = execute_sql(
            database.get(),
            "DELETE FROM google_accounts WHERE google_sub=$1",
            {session.google_sub});
        if (!deleted || PQresultStatus(deleted.get()) != PGRES_COMMAND_OK) return database_unavailable(database.get());
        crow::response response("{\"ok\":true}");
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response.set_header("Cache-Control", "no-store");
        response.add_header("Set-Cookie", "app_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
        response.add_header("Set-Cookie", "csrf_token=; Path=/; Max-Age=0; Secure; SameSite=Strict");
        return response;
    });

    CROW_ROUTE(app, "/api/my/playlists").methods(crow::HTTPMethod::GET)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        std::vector<std::pair<std::string, std::string>> parameters = {
            {"part", "snippet,status,contentDetails"}, {"mine", "true"}, {"maxResults", "50"}
        };
        const char* page_token = request.url_params.get("pageToken");
        if (page_token != nullptr && std::strlen(page_token) > 512) {
            return json_error(400, "播放清單分頁代碼格式不正確。");
        }
        if (page_token != nullptr) {
            parameters.emplace_back("pageToken", page_token);
        }
        return forward_user_youtube_response(youtube_user_request(
            access_token, "GET", "playlists", parameters));
    });

    CROW_ROUTE(app, "/api/my/playlists").methods(crow::HTTPMethod::POST)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");

        crow::json::rvalue input;
        if (!read_json_body(request, input)) return json_error(400, "播放清單資料格式不正確。");
        const std::string title = json_request_string(input, "title");
        const std::string description = json_request_string(input, "description");
        const std::string privacy = json_request_string(input, "privacyStatus");
        if (title.empty() || title.size() > 150 || description.size() > 5000 ||
            (privacy != "private" && privacy != "unlisted" && privacy != "public")) {
            return json_error(400, "請提供有效標題、描述及清單隱私設定。");
        }
        crow::json::wvalue payload;
        payload["snippet"]["title"] = title;
        payload["snippet"]["description"] = description;
        payload["status"]["privacyStatus"] = privacy;
        return forward_user_youtube_response(youtube_user_request(
            access_token, "POST", "playlists", {{"part", "snippet,status"}}, payload.dump()));
    });

    CROW_ROUTE(app, "/api/my/playlists").methods(crow::HTTPMethod::PUT)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");

        crow::json::rvalue input;
        if (!read_json_body(request, input)) return json_error(400, "播放清單資料格式不正確。");
        const std::string playlist_id = json_request_string(input, "playlistId");
        const std::string title = json_request_string(input, "title");
        const std::string description = json_request_string(input, "description");
        const std::string privacy = json_request_string(input, "privacyStatus");
        if (!valid_playlist_id(playlist_id) || title.empty() || title.size() > 150 ||
            description.size() > 5000 ||
            (privacy != "private" && privacy != "unlisted" && privacy != "public")) {
            return json_error(400, "請提供有效的播放清單 ID、標題、描述及隱私設定。");
        }
        crow::json::wvalue payload;
        payload["id"] = playlist_id;
        payload["snippet"]["title"] = title;
        payload["snippet"]["description"] = description;
        payload["status"]["privacyStatus"] = privacy;
        return forward_user_youtube_response(youtube_user_request(
            access_token, "PUT", "playlists", {{"part", "snippet,status"}}, payload.dump()));
    });

    CROW_ROUTE(app, "/api/my/playlists").methods(crow::HTTPMethod::DELETE)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");
        const char* id_param = request.url_params.get("id");
        const std::string playlist_id = id_param == nullptr ? std::string() : std::string(id_param);
        if (!valid_playlist_id(playlist_id)) return json_error(400, "播放清單 ID 格式不正確。");
        return forward_user_youtube_response(youtube_user_request(
            access_token, "DELETE", "playlists", {{"id", playlist_id}}));
    });

    CROW_ROUTE(app, "/api/my/playlist-items").methods(crow::HTTPMethod::GET)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        const char* id_param = request.url_params.get("playlistId");
        const std::string playlist_id = id_param == nullptr ? std::string() : std::string(id_param);
        if (!valid_playlist_id(playlist_id)) return json_error(400, "播放清單 ID 格式不正確。");
        std::vector<std::pair<std::string, std::string>> parameters = {
            {"part", "snippet,contentDetails"}, {"playlistId", playlist_id}, {"maxResults", "50"}
        };
        const char* page_token = request.url_params.get("pageToken");
        if (page_token != nullptr && std::strlen(page_token) > 512) {
            return json_error(400, "影片分頁代碼格式不正確。");
        }
        if (page_token != nullptr) {
            parameters.emplace_back("pageToken", page_token);
        }
        return forward_user_youtube_response(youtube_user_request(
            access_token, "GET", "playlistItems", parameters));
    });

    CROW_ROUTE(app, "/api/my/playlist-items").methods(crow::HTTPMethod::POST)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");

        crow::json::rvalue input;
        if (!read_json_body(request, input)) return json_error(400, "影片資料格式不正確。");
        const std::string playlist_id = json_request_string(input, "playlistId");
        const std::string video_id = json_request_string(input, "videoId");
        if (!valid_playlist_id(playlist_id) || !is_valid_video_id(video_id)) {
            return json_error(400, "播放清單或影片 ID 格式不正確。");
        }
        crow::json::wvalue payload;
        payload["snippet"]["playlistId"] = playlist_id;
        payload["snippet"]["resourceId"]["kind"] = "youtube#video";
        payload["snippet"]["resourceId"]["videoId"] = video_id;
        return forward_user_youtube_response(youtube_user_request(
            access_token, "POST", "playlistItems", {{"part", "snippet"}}, payload.dump()));
    });

    CROW_ROUTE(app, "/api/my/playlist-items").methods(crow::HTTPMethod::DELETE)([](const crow::request& request) {
        PgConnection database;
        AccountSession session;
        std::string access_token;
        crow::response error;
        if (!prepare_user_api(request, database, session, access_token, error)) return error;
        if (!validate_csrf(request, session)) return json_error(403, "安全驗證失敗，請重新載入頁面。");
        const char* playlist_param = request.url_params.get("playlistId");
        const char* item_param = request.url_params.get("itemId");
        const std::string playlist_id = playlist_param == nullptr ? std::string() : std::string(playlist_param);
        const std::string item_id = item_param == nullptr ? std::string() : std::string(item_param);
        if (!valid_playlist_id(playlist_id) || !valid_playlist_id(item_id)) {
            return json_error(400, "播放清單或項目 ID 格式不正確。");
        }

        const YouTubeResponse item_response = youtube_user_request(
            access_token, "GET", "playlistItems",
            {{"part", "snippet"}, {"id", item_id}});
        if (item_response.request_status != CURLE_OK ||
            item_response.http_status < 200 || item_response.http_status >= 300) {
            return forward_user_youtube_response(item_response);
        }
        const auto item_data = crow::json::load(item_response.body);
        if (!item_data || item_data.t() != crow::json::type::Object ||
            !item_data.has("items") || item_data["items"].t() != crow::json::type::List ||
            item_data["items"].size() != 1 || item_data["items"][0].t() != crow::json::type::Object ||
            !item_data["items"][0].has("snippet") ||
            item_data["items"][0]["snippet"].t() != crow::json::type::Object ||
            read_json_string(item_data["items"][0]["snippet"], "playlistId") != playlist_id) {
            return json_error(404, "找不到該播放清單中的影片項目。");
        }
        return forward_user_youtube_response(youtube_user_request(
            access_token, "DELETE", "playlistItems", {{"id", item_id}}));
    });

    CROW_ROUTE(app, "/watch")([](const crow::request& req) {
        const char* video_param = req.url_params.get("v");
        if (video_param == nullptr) {
            return crow::response(400, "請提供 YouTube 影片 ID，例如：/watch?v=dQw4w9WgXcQ");
        }

        const std::string video_id(video_param);
        if (!is_valid_video_id(video_id)) {
            return crow::response(400, "YouTube 影片 ID 格式不正確。");
        }

        const std::string page =
            "<!DOCTYPE html><html lang='zh-Hant'><head><meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>YouTube 播放</title>"
            "<style>html,body{margin:0;width:100%;height:100%;background:#000}"
            "iframe{width:100%;height:100%;border:0}</style></head><body>"
            "<iframe src='https://www.youtube.com/embed/" + video_id +
            "' title='YouTube 播放器' allow='accelerometer; autoplay; clipboard-write; encrypted-media; "
            "gyroscope; picture-in-picture; web-share' allowfullscreen></iframe>"
            "</body></html>";
        crow::response response(page);
        response.set_header("Content-Type", "text/html; charset=utf-8");
        return response;
    });

    CROW_ROUTE(app, "/api/search")([](const crow::request& req) {
        const char* query_param = req.url_params.get("q");
        if (query_param == nullptr) {
            return json_error(400, "請輸入搜尋關鍵字。");
        }

        const std::string query(query_param);
        if (query.empty() || query.size() > 200) {
            return json_error(400, "搜尋關鍵字長度須介於 1 到 200 個字元。");
        }

        return handle_youtube_api("search", {
            {"part", "snippet"},
            {"type", "video"},
            {"maxResults", "12"},
            {"q", query}
        });
    });

    CROW_ROUTE(app, "/api/popular")([](const crow::request& req) {
        std::vector<std::pair<std::string, std::string>> parameters = {
            {"part", "snippet,contentDetails"},
            {"chart", "mostPopular"},
            {"regionCode", "TW"},
            {"maxResults", "24"}
        };
        const char* category_id = req.url_params.get("categoryId");
        if (category_id != nullptr && *category_id != '\0') {
            parameters.emplace_back("videoCategoryId", category_id);
        }
        return handle_youtube_api("videos", parameters);
    });

    CROW_ROUTE(app, "/api/details")([](const crow::request& req) {
        const char* ids_param = req.url_params.get("ids");
        if (ids_param == nullptr || *ids_param == '\0') {
            return json_error(400, "請提供影片 ID。");
        }

        const std::string ids(ids_param);
        static const std::regex video_ids_pattern(
            "^[a-zA-Z0-9_-]{11}(,[a-zA-Z0-9_-]{11}){0,11}$");
        if (!std::regex_match(ids, video_ids_pattern)) {
            return json_error(400, "影片 ID 格式不正確。");
        }

        return handle_youtube_api("videos", {
            {"part", "contentDetails"},
            {"id", ids}
        });
    });

    CROW_ROUTE(app, "/api/categories")([] {
        return handle_youtube_api("videoCategories", {
            {"part", "snippet"},
            {"regionCode", "TW"}
        });
    });

    const char* port_env = std::getenv("PORT");
    const int port = port_env != nullptr ? std::stoi(port_env) : 18080;

    std::cout << "YouTube 影片探索服務正在連接埠 " << port << " 運行。" << std::endl;
    app.port(port).bindaddr("0.0.0.0").multithreaded().run();
    curl_global_cleanup();
}
