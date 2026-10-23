# YouTube 影片探索

C++17、Crow 網頁服務，支援公開影片探索，以及透過 Google OAuth 管理登入者自己的 YouTube 播放清單。

## Render 與 Google 登入設定

Google 登入流程已包含在服務中，但必須先設定 Google Cloud OAuth 用戶端與 Render 資料庫／環境變數，登入按鈕才會啟用。以下以目前 Render 網址 `https://c-youtube-api.onrender.com` 為例；若改用自訂網域，請將各處網址一致替換。

### 1. 建立 Google Cloud OAuth 用戶端

1. 在 Google Cloud Console 建立或選取專案，並在 API Library 啟用 **YouTube Data API v3**。
2. 前往 **Google Auth Platform**（部分介面仍顯示 **APIs & Services > OAuth consent screen**），設定應用程式名稱、使用者支援電子郵件及開發者聯絡電子郵件。
3. 設定 Audience。一般個人 Google 帳戶選 **External**；先維持 **Testing**，並在 **Test users** 加入要測試登入的 Google 帳戶。
4. 建立 OAuth Client，類型選 **Web application**。在 **Authorized redirect URIs** 加入以下完整網址（不要加尾端斜線）：

   `https://c-youtube-api.onrender.com/auth/callback`

   這是伺服器端 OAuth 流程，不需要設定 JavaScript origins。
5. 複製產生的 Client ID 與 Client Secret，下一步直接填入 Render 的環境變數；不要貼到聊天、原始碼或 Git。

目前登入會要求 `openid`、`email`、`profile` 及 `https://www.googleapis.com/auth/youtube.force-ssl`，以便辨識帳戶並管理其播放清單。OAuth 測試模式只能讓已列入 Test users 的帳戶使用；測試狀態下的 refresh token 可能在 7 天後失效。正式對外開放前，須依 Google 當時要求完成必要的 OAuth／YouTube API 驗證及發布程序。

### 2. 設定 Render

1. 在 Render 建立 **PostgreSQL** 資料庫，並將該資料庫的 **Internal Database URL** 設為 Web Service 的 `DATABASE_URL`。
2. 在 Web Service 的 **Environment** 頁面逐一加入下表變數。Client Secret、資料庫 URL 和加密金鑰都應使用 Render 的環境變數介面，不要提交至 Git。

| 環境變數 | 值 |
| --- | --- |
| `DATABASE_URL` | Render Postgres 的 Internal Database URL |
| `GOOGLE_CLIENT_ID` | Google Cloud Web application OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | 該 OAuth 用戶端的 Client Secret |
| `GOOGLE_REDIRECT_URI` | `https://c-youtube-api.onrender.com/auth/callback` |
| `TOKEN_ENCRYPTION_KEY` | 32 位元組金鑰的 64 字元十六進位值 |
| `YOUTUBE_API_KEY` | 公開搜尋、熱門影片及分類 API 使用的 API key |

可在自己的電腦產生 `TOKEN_ENCRYPTION_KEY`，並直接貼到 Render，不要傳送給他人：

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$key = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
$rng.Dispose()
$key
```

3. 儲存環境變數並重新部署 Web Service。OAuth callback URL 必須同時與 Google Cloud 的 **Authorized redirect URI** 和 Render 的 `GOOGLE_REDIRECT_URI` 完全一致。
4. 開啟 `https://c-youtube-api.onrender.com/api/auth/status`。未登入時預期回傳 `{"authenticated":false,"configured":true}`；若 `configured` 仍是 `false`，請檢查上述五項 OAuth／資料庫設定及金鑰格式（`YOUTUBE_API_KEY` 不決定登入按鈕是否啟用）。
5. 回到網站按 **登入 Google**，選擇已加入 Test users 的帳戶，並同意 YouTube 播放清單管理權限。成功後應返回網站並顯示已登入狀態。

### 常見登入錯誤

- **按鈕顯示「登入未設定」**：`/api/auth/status` 的 `configured` 為 `false`。檢查同一回應的 `configurationError` 欄位，或在 Render Web Service 的 **Logs** 查看 `OAuth configuration error:` 訊息。日誌只會列出缺少的變數名稱或金鑰格式要求，不會記錄任何設定值。
- **`redirect_uri_mismatch`**：確認 Google Cloud 和 Render 的 callback URL 都是 `https://c-youtube-api.onrender.com/auth/callback`，包含 `https`、網域及路徑且沒有尾端斜線。
- **應用程式存取遭拒或測試者無法登入**：確認 Audience 為 External，且登入帳戶已加入 Test users；若要正式開放，完成 Google 要求的驗證。
- **登入後提示授權不足**：重新登入並同意 YouTube 播放清單管理權限；確認已啟用 YouTube Data API v3。
- **資料庫錯誤**：查看 Render Web Service logs。連線失敗會提示檢查 `DATABASE_URL`、Postgres 狀態及網路；資料表初始化失敗會記錄 PostgreSQL SQLSTATE。確認 `DATABASE_URL` 使用同一 Render workspace 中 Postgres 的 Internal Database URL。

遺失或更換 `TOKEN_ENCRYPTION_KEY` 會使已保存的 refresh token 無法解密；輪替前必須先規劃重新授權或安全遷移。

首次使用 Google OAuth 時，服務會在 Postgres 建立所需資料表。播放清單本身由 YouTube 保存；Postgres 保存帳戶識別、加密後 refresh token、短期登入 session 及 OAuth state。解除 Google 授權會請求 Google 撤銷 token，並刪除本站儲存的帳戶和 session。

網站的 `/privacy` 與 `/terms` 頁面是實作範本。正式公開前，營運者必須補上可聯絡的實際方式、確認資料處理說明符合實際作法，並準備 Google 要求的自有已驗證網域、首頁、隱私權政策及其他 OAuth 品牌資料。頁面存在不代表法律審查或 Google OAuth 驗證已完成。

## 本機建置

需要 C++17、CMake、Standalone Asio、libcurl、OpenSSL 及 PostgreSQL client development headers：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Docker 部署會使用專案中的 `Dockerfile`。
