/**
 * 概念版听歌等级榜（全球年榜/省月榜/市周榜 + 听歌经验倍率）
 *
 * 对应酷狗概念版「我的 → 听歌等级」页的榜单与倍率数据源：
 *   POST https://userinfoservice.kugou.com/v1/youth/get_rank_list
 *
 * 该接口来自概念版内嵌 H5 页（mobileCallProtocol 请求族），请求体由页面脚本本地加密，
 * 但加密全程可本地还原，无需依赖客户端密文：
 * - params = AES-256-CBC/PKCS7( JSON.stringify({token, ...业务参数}) )，小写 hex
 *     key = md5(keyStr) 小写 hex 全 32 字符（Latin1 字节），iv = md5(keyStr) hex 的第 16~32 字符
 *     （等价于 util.cryptoAesEncrypt 的默认行为）
 * - p = 概念版 H5 页面脚本（kg-rsa）的自定义 RSA：明文反转写入 128 字节块首，块结构
 *     [明文反转][0x00][随机非零填充][0x02][0x00]，按小端装配后 raw RSA，输出 256 位小写 hex
 *     （见 util.cryptoH5RsaEncryptHex；模数为 H5 页面内嵌公钥，与 APP 端公钥不同）
 * - p 明文 = {"clienttime":"<毫秒>","key":"<16 位随机 keyStr>"}
 * - query 带 srcappid=2919，signature 用 Web 盐（signatureWebParams），
 *   签名串 = 盐 + query 按字典序 k=v 拼接 + JSON.stringify(body) + 盐
 *
 * 客户端行为：
 * - 页面每次加载并发调 3 次，对应页面的三个榜单 tab：全球年榜 / 省月榜 / 市周榜；
 *   切换榜单 tab 触发单发。实测指纹：全球年榜 total 1000（rank_type=2）、
 *   省月榜/市周榜 total 100，榜单 top3 分数量级 年榜 >> 月榜 >> 周榜。
 *   （H5 本人排名横幅文案写作「你的听歌数据在全球月排名」，与 tab 标签「全球年榜」
 *   及 tab key `globalYear` 不一致，为产品文案笔误，以 tab 定义为准）
 *   响应 `rank_type` 不足以单独区分榜单，建议结合首条目与 total 判断
 * - 响应中大量 `"total":500` 是概念版会员的 vip_limit_quota（每日配额），与榜单 total 无关
 * - 响应带 `p_speed_info`（倍率档位表 {p0:"1",p1:"1.5",p2:"2",p3:"2.5"}）与本人 `p_speed`
 * - 本人区带 `rank_percent`（排名百分位，页面显示为「TOP xx%」角标，如 43 → TOP43%）
 *   与 `rank_distance`（距榜首分数差）、`province_id`/`city_id`（行政区划）
 * - 榜单条目含每人的 `p_speed`（实际倍率）与完整 `vipinfo`
 *
 * 服务端校验要点（实测归纳）：
 * - userid 必须与 token 所属账号一致，否则 error_code=20018
 * - mid / uuid / dfid 均不做强校验（传 '-' 亦可）
 * - clienttime 秒级/毫秒级、p 与 query 的一致性均不强制（实测），
 *   实现保持与客户端一致的毫秒同源写法
 *
 * 倍率判定规则（服务端逻辑，实测归纳）：
 *   1×   = 非会员 / 免费试用概念版 VIP（busi_vip.is_paid_vip=0）
 *   1.5× = 月度普通会员（user_type=13 且 user_y_type=0；概念版付费非年费）
 *   2×   = 年费普通会员（user_y_type=13/5）或 月度豪华/超级 VIP（user_type=21 且 user_y_type=0）
 *   2.5× = 年费豪华/超级 VIP（user_type=21 且 user_y_type=21）
 *
 * @param {number} [params.rank_type] - 榜单类型：2=全球年榜，3=省月榜，4=市周榜（默认 2）
 * @param {number} [params.page] - 页码（默认 1）
 * @param {number} [params.page_size] - 每页条数（默认 30，客户端页面使用 100）
 * @param {string} [params.p] - 旧用法兼容：客户端请求体中的 p 密文（hex），传入则整体透传
 * @param {string} [params.params] - 旧用法兼容：客户端请求体中的 params 密文（hex），与 p 成对传入
 * @param {string} [params.userid] - 用户 ID（默认取 cookie.userid；必须与 token 所属账号一致）
 * @param {string} [params.mid] - 设备 mid（默认取 cookie.KUGOU_API_MID，可不传）
 * @param {string} [params.dfid] - 设备 dfid（默认取 cookie.dfid，可不传）
 * @param {string} [params.kg_devid] - 可选，请求头 KG-DEVID（设备绑定串，提高请求成功率）
 * @param {Object} params.cookie - 登录态（token/userid）
 * @returns {Promise<{status: number, body: Object}>}
 */
const { discoveryCards, srcappid, signatureWebParams, cryptoAesEncrypt, cryptoH5RsaEncryptHex } = require('../util');
const { CONCEPT_APPID, CONCEPT_CLIENTVER } = discoveryCards;

module.exports = (params, useAxios) => {
  const cookie = params?.cookie || {};
  const userid = `${params?.userid || cookie?.userid || ''}`;
  const token = `${params?.token || cookie?.token || ''}`;
  if (!userid || !token) {
    return Promise.reject({
      status: 502,
      body: {
        status: 0,
        error_code: 1,
        error: '缺少 userid / token：听歌等级榜需要登录态，userid 必须与 token 所属账号一致。',
      },
    });
  }

  const rankType = Number(params?.rank_type ?? 2);
  const page = Number(params?.page ?? 1);
  const pageSize = Number(params?.page_size ?? 30);

  // 与客户端一致：query 与 p 内 clienttime 同源（同一毫秒值；实测服务端不强制）
  const clienttime = `${Date.now()}`;

  let data;
  if (params?.p && params?.params) {
    // 旧用法兼容：直接透传客户端密文体（key 顺序与客户端一致：userid → p → params）
    data = { userid, p: `${params.p}`, params: `${params.params}` };
  } else {
    // 本地构造：params = AES(JSON)，p = RSA(JSON.stringify({clienttime, key}))
    const aes = cryptoAesEncrypt({
      token,
      page,
      page_size: pageSize,
      rank_type: rankType,
      busi_type: 'concept',
      get_type: 3,
    });
    data = {
      userid,
      p: cryptoH5RsaEncryptHex(JSON.stringify({ clienttime, key: aes.key })),
      params: aes.str,
    };
  }

  const query = {
    appid: CONCEPT_APPID,
    mid: `${params?.mid || cookie?.KUGOU_API_MID || cookie?.mid || '-'}`,
    uuid: '-',
    dfid: `${params?.dfid || cookie?.dfid || '-'}`,
    userid,
    token,
    clientver: CONCEPT_CLIENTVER,
    clienttime,
    srcappid,
  };
  query.signature = signatureWebParams(query, JSON.stringify(data));

  return useAxios({
    baseURL: 'https://userinfoservice.kugou.com',
    url: '/v1/youth/get_rank_list',
    method: 'POST',
    data,
    params: query,
    clearDefaultParams: true, // 顶层参数/签名已自行构造，避免注入默认参数破坏签名
    cookie,
    headers: {
      'User-Agent': `Android16-1070-${CONCEPT_CLIENTVER}-130-0-mobileCallProtocol-wifi`,
      'Content-Type': 'application/json',
      'x-router': 'userinfoservice.kugou.com',
      'KG-THash': '26c94b9',
      'KG-Rec': '1',
      'KG-RC': '1',
      'KG-RFB': '0',
      'KG-FAKE': userid,
      'KG-CLIENTTIMEMS': `${Date.now()}`,
      ...(params?.kg_devid ? { 'KG-DEVID': `${params.kg_devid}` } : {}),
    },
  });
};
