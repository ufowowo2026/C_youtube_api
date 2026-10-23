#include "crow.h"
#include <curl/curl.h>

#include <cstdlib>
#include <iostream>
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
    crow::response response(status, "{\"error\":\"" + message + "\"}");
    response.set_header("Content-Type", "application/json; charset=utf-8");
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

crow::response forward_youtube_response(const YouTubeResponse& result) {
    if (result.request_status != CURLE_OK) {
        std::cerr << "YouTube API 請求失敗：" << curl_easy_strerror(result.request_status) << std::endl;
        return json_error(502, "無法連線至 YouTube 服務，請稍後再試。");
    }
    if (result.http_status < 200 || result.http_status >= 300) {
        std::cerr << "YouTube API 回傳 HTTP " << result.http_status << std::endl;
        return json_error(502, "YouTube 服務暫時無法使用，請確認 API 設定或稍後再試。");
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
    return forward_youtube_response(result);
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
    #videos { display: grid; grid-template-columns: repeat(auto-fill, minmax(245px, 1fr)); gap: 28px 16px; }
    .video-card { min-width: 0; }
    .video-card img { display: block; width: 100%; aspect-ratio: 16 / 9; object-fit: cover; border-radius: 12px; background: #222; }
    .video-card h2 { margin: 10px 0 6px; font-size: 16px; line-height: 1.4; }
    .video-card p { margin: 4px 0; color: #aaa; line-height: 1.45; }
    .video-card button { margin-top: 6px; padding: 8px 14px; border-radius: 18px; }
    #player-panel { position: relative; margin: 0 0 26px; }
    #player { width: 100%; aspect-ratio: 16 / 9; border: 0; background: #000; }
    #close-player { position: absolute; top: 10px; right: 10px; padding: 8px 12px; border-radius: 18px; }
    [hidden] { display: none !important; }
    @media (max-width: 700px) {
      header { gap: 12px; padding: 0 12px; }
      .brand { font-size: 16px; }
      form { width: 100%; }
      .layout { grid-template-columns: 1fr; }
      nav { position: static; display: flex; height: auto; padding: 8px 12px; border-right: 0; border-bottom: 1px solid #282828; }
      nav button { width: auto; flex: 1; margin: 0; text-align: center; }
      main { padding: 18px 14px 36px; }
      #videos { grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 20px 10px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">YouTube 探索</div>
    <form id="search-form" role="search">
      <input id="query" type="search" maxlength="200" placeholder="搜尋影片" aria-label="搜尋影片" required>
      <button type="submit">搜尋</button>
    </form>
  </header>
  <div class="layout">
    <nav aria-label="主要導覽">
      <button type="button" data-view="popular">首頁 / 熱門</button>
      <button type="button" data-view="search">搜尋結果</button>
    </nav>
    <main>
      <section id="player-panel" hidden>
        <button id="close-player" type="button">關閉播放器</button>
        <div id="player"></div>
      </section>
      <h1 id="heading">熱門影片</h1>
      <div id="categories" aria-label="影片分類"></div>
      <p id="status" role="status"></p>
      <section id="videos" aria-live="polite"></section>
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
    let player = null;
    let playerReady = false;
    let pendingVideoId = null;

    function closeVideoPlayer() {
      pendingVideoId = null;
      playerPanel.hidden = true;
      if (playerReady && player) player.stopVideo();
    }

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
        playerVars: { playsinline: 1, rel: 0 },
        events: {
          onReady: () => {
            playerReady = true;
            if (pendingVideoId) player.loadVideoById(pendingVideoId);
          }
        }
      });
    };

    function playVideo(videoId) {
      if (!/^[a-zA-Z0-9_-]{11}$/.test(videoId)) return;
      playerPanel.hidden = false;
      pendingVideoId = videoId;
      if (playerReady && player) player.loadVideoById(videoId);
      playerPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function displayVideos(items) {
      videos.replaceChildren();
      for (const item of items || []) {
        const videoId = typeof item.id === 'string' ? item.id : item.id && item.id.videoId;
        const snippet = item.snippet;
        if (!videoId || !snippet) continue;

        const card = document.createElement('article');
        card.className = 'video-card';
        const thumbnail = document.createElement('img');
        const thumbnails = snippet.thumbnails || {};
        thumbnail.src = (thumbnails.medium && thumbnails.medium.url) ||
          (thumbnails.high && thumbnails.high.url) ||
          (thumbnails.default && thumbnails.default.url) || '';
        thumbnail.alt = '';
        thumbnail.loading = 'lazy';

        const title = document.createElement('h2');
        title.textContent = snippet.title || '未命名影片';
        const channel = document.createElement('p');
        const duration = formatDuration(item.contentDetails && item.contentDetails.duration);
        channel.textContent = [snippet.channelTitle, duration].filter(Boolean).join(' · ');
        const description = document.createElement('p');
        description.textContent = snippet.description || '';
        const playButton = document.createElement('button');
        playButton.type = 'button';
        playButton.textContent = '播放';
        playButton.addEventListener('click', () => playVideo(videoId));

        card.append(thumbnail, title, channel, description, playButton);
        videos.append(card);
      }
      if (!videos.children.length) status.textContent = '找不到符合的影片。';
      else status.textContent = '';
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

    const iframeApi = document.createElement('script');
    iframeApi.src = 'https://www.youtube.com/iframe_api';
    document.head.append(iframeApi);

    loadCategories();
    loadVideoList('/api/popular', '熱門影片');
  </script>
</body>
</html>)html";

}  // namespace

int main() {
    const CURLcode curl_status = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_status != CURLE_OK) {
        std::cerr << "無法初始化 HTTP 用戶端：" << curl_easy_strerror(curl_status) << std::endl;
        return 1;
    }

    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([] {
        crow::response response(HOME_PAGE);
        response.set_header("Content-Type", "text/html; charset=utf-8");
        return response;
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
