/**
 * 业务功能性端点集中配置（安全整改 #10 方案 B：集中配置化）。
 *
 * - 默认值与原硬编码值完全一致（等价变换，不改任何对外行为）；
 * - 环境切换只改本文件（或通过同名环境变量覆盖），不改业务源码；
 * - 同名环境变量优先级高于本文件默认值（如 OIDC_PROD_BASE）。
 */
module.exports = {
  // OIDC 回调网关（prod 正式环境 / beta 测试环境）
  // beta 域名说明：beta.apig.openlibing.com 已确认 DNS 指向华为云 APIG，但证书尚未
  // 绑定该域名（TLS 握手返回 *.apic.cn-southwest-2.huaweicloudapis.com 默认证书）。
  // 当前临时使用已发布 /action-api 接口的 APIG 域名，保证链路可测；平台绑定证书后应切回。
  OIDC_PROD_BASE: 'https://apig.openlibing.com',
  OIDC_BETA_BASE: 'https://174e1b821a8446f38998a67186ba766e.apic.cn-southwest-2.huaweicloudapis.com',

  // OBS：通用 SARIF 结果统一存放（后端 SarifParseServiceImpl 匿名 HTTP GET 下载）
  // 上传端点 server 由 OIDC SDK configure 动态返回 region，不在此写死
  OBS_BUCKET: 'openlibing-gitcode-action',
  OBS_READ_ENDPOINT: 'https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com',

  // CodeArts Check API host（按 region 动态拼：{HOST_PREFIX}.{region}.{API_DOMAIN}）
  CODEARTS_HOST_PREFIX: 'codecheck-ext',
  CODEARTS_API_DOMAIN: 'myhuaweicloud.com'
};
