# YouTube 影片探索

C++17、Crow 網頁服務，支援公開影片探索，以及透過 Google OAuth 管理登入者自己的 YouTube 播放清單。

## Render 部署

建立 Render Postgres，並將下列環境變數加入 Web Service。請使用 Render 提供的內部資料庫連線字串；不要把任何密鑰提交至 Git。

| 環境變數 | 用途 |
| --- | --- |
| `DATABASE_URL` | Render Postgres 連線字串 |
| `GOOGLE_CLIENT_ID` | Google Cloud Web application OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret |
| `GOOGLE_REDIRECT_URI` | 完整 callback URL，例如 `https://你的網域/auth/callback` |
| `TOKEN_ENCRYPTION_KEY` | 32 位元組金鑰的 64 字元十六進位值，用於 AES-256-GCM 加密 refresh token |
| `YOUTUBE_API_KEY` | 公開搜尋、熱門影片及分類 API 使用的 API key |

可在安全的本機環境以 `openssl rand -hex 32` 產生 `TOKEN_ENCRYPTION_KEY`，再將輸出直接設定為 Render Secret Environment Variable。遺失或更換此金鑰會使既有 token 無法解密；輪替前必須先規劃重新授權或安全遷移。

在 Google Cloud Console：

1. 啟用 YouTube Data API v3，並建立 OAuth 用戶端類型為 **Web application**。
2. 將 `GOOGLE_REDIRECT_URI` 完整加入 Authorized redirect URIs。
3. 設定 OAuth consent screen、支援聯絡方式及使用者類型；此服務要求 `openid`、`email`、`profile` 及 `https://www.googleapis.com/auth/youtube.force-ssl` 權限。
4. 對外開放前，請確認 Google 對 YouTube 權限的驗證要求及 YouTube API 合規要求均已完成。

OAuth consent screen 若維持 External / Testing，必須將測試者加入 test users；測試狀態下的授權可能需要在 7 天後重新授權，不能視為正式長期使用。對外正式使用前，請依 Google 當時的規則完成發布與必要的 OAuth／YouTube API 驗證。

首次使用 Google OAuth 時，服務會在 Postgres 建立所需資料表。播放清單本身由 YouTube 保存；Postgres 保存帳戶識別、加密後 refresh token、短期登入 session 及 OAuth state。解除 Google 授權會請求 Google 撤銷 token，並刪除本站儲存的帳戶和 session。

網站的 `/privacy` 與 `/terms` 頁面是實作範本。正式公開前，營運者必須補上可聯絡的實際方式、確認資料處理說明符合實際作法，並準備 Google 要求的自有已驗證網域、首頁、隱私權政策及其他 OAuth 品牌資料。頁面存在不代表法律審查或 Google OAuth 驗證已完成。

## 本機建置

需要 C++17、CMake、Standalone Asio、libcurl、OpenSSL 及 PostgreSQL client development headers：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Docker 部署會使用專案中的 `Dockerfile`。
