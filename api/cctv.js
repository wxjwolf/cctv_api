const CryptoJS = require('crypto-js');

// 频道映射
const channelMap = {
  'cctv1': '11200132825562653886',
  'cctv2': '12030532124776958103',
  'cctv4': '10620168294224708952',
  'cctv7': '8516529981177953694',
  'cctv9': '7252237247689203957',
  'cctv10': '14589146016461298119',
  'cctv12': '13180385922471124325',
  'cctv13': '16265686808730585228',
  'cctv17': '4496917190172866934',
  'cctv4k': '2127841942201075403'
};

module.exports = async (req, res) => {
  // 设置CORS头
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // 处理OPTIONS请求
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 只允许GET请求
  if (req.method !== 'GET') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  try {
    const { id = 'cctv1', q = 'lg' } = req.query;

    // 验证参数
    if (!channelMap[id]) {
      return res.status(400).json({
        success: false,
        error: 'Invalid channel ID'
      });
    }

    if (!['lg', 'cq', 'gq'].includes(q)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid quality parameter'
      });
    }

    const articleId = channelMap[id];
    const t = Math.floor(Date.now() / 1000);

    // 生成签名
    const sail = CryptoJS.MD5(`articleId=${articleId}&scene_type=6`).toString();
    const w = `&&&20000009&${sail}&${t}&emas.feed.article.live.detail&1.0.0&&&&&`;
    const k = "emasgatewayh5";
    const sign = CryptoJS.HmacSHA256(w, k).toString();

    // 构建请求头
    const clientId = CryptoJS.MD5(t.toString()).toString();
    const headers = {
      'cookieuid': clientId,
      'from-client': 'h5',
      'referer': 'https://m-live.cctvnews.cctv.com/',
      'x-emas-gw-appkey': '20000009',
      'x-emas-gw-pv': '6.1',
      'x-emas-gw-sign': sign,
      'x-emas-gw-t': t.toString(),
      'x-req-ts': (t * 1000).toString(),
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    };

    // 获取直播数据
    const apiUrl = `https://emas-api.cctvnews.cctv.com/h5/emas.feed.article.live.detail/1.0.0?articleId=${articleId}&scene_type=6`;
    
    const response = await fetch(apiUrl, { headers });
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    const data = await response.json();
    
    // 解码响应数据
    const decodedResponse = JSON.parse(
      CryptoJS.enc.Utf8.stringify(
        CryptoJS.enc.Base64.parse(data.response)
      )
    );
    
    const liveData = decodedResponse.data;

    // 获取对应画质的URL
    let authUrl;
    const authResult = liveData.live_room.liveCameraList[0].pullUrlList[0].authResultUrl[0];
    
    if (q === 'lg') {
      authUrl = authResult.authUrl;
    } else if (q === 'cq') {
      authUrl = authResult.demote_urls[1].authUrl;
    } else if (q === 'gq') {
      authUrl = authResult.demote_urls[0].authUrl;
    }

    // 解密URL
    const dk = liveData.dk;
    const key = dk.substring(0, 8) + t.toString().slice(-8);
    const iv = dk.substring(dk.length - 8) + t.toString().substring(0, 8);
    
    const liveUrl = decryptAES(authUrl, key, iv);

    // 重定向到直播流
    res.setHeader('Location', liveUrl);
    return res.status(302).end();

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// AES解密函数
function decryptAES(encryptedData, key, iv) {
  try {
    // Base64解码
    const encryptedBytes = CryptoJS.enc.Base64.parse(encryptedData);
    
    // 解析key和iv
    const keyBytes = CryptoJS.enc.Utf8.parse(key);
    const ivBytes = CryptoJS.enc.Utf8.parse(iv);
    
    // AES-CBC解密
    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: encryptedBytes },
      keyBytes,
      { 
        iv: ivBytes,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    return CryptoJS.enc.Utf8.stringify(decrypted);
  } catch (error) {
    throw new Error(`AES decryption failed: ${error.message}`);
  }
}
