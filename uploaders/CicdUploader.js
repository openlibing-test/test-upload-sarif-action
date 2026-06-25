const axios = require('axios');

class CicdUploader {
  constructor(config = {}) {
    this.baseUrl = config.cicdUrl || 'http://localhost:8080';
    this.timeout = config.timeout || 30000;

    const headers = { 'Content-Type': 'application/json' };

    // APIG 网关鉴权：将 AppKey、AppSecret、AppCode 作为请求头
    if (config.apigAppKey) headers['Appkey'] = config.apigAppKey;
    if (config.apigAppSecret) headers['AppSecret'] = config.apigAppSecret;
    if (config.apigAppCode) headers['X-Apig-AppCode'] = config.apigAppCode;

    this.axiosInstance = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: headers
    });
  }

  /**
   * 上传安全编译选项扫描结果到 cicd 服务
   * @param {object} scanResult - 扫描结果，包含 summary 和 details
   * @param {object} options - 上传选项（gitUrl、runNumber、packageName 等）
   * @returns {Promise<{success: boolean, recordId?: string, error?: string}>}
   */
  async upload(scanResult, options = {}) {
    const { summary = {}, details = [] } = scanResult;

    const payload = {
      gitUrl: options.gitUrl,
      pipelineRunId: options.pipelineRunId,
      runNumber: options.runNumber,
      packageName: options.packageName,
      overviewData: summary,
      fileDetails: details,
      detectionStartedAt: options.startTime,
      detectionCompletedAt: options.endTime,
      status: options.status || 0
    };

    if (options.errorMessage) {
      payload.errorMessage = options.errorMessage;
    }

    try {
      const response = await this.axiosInstance.post('/build-artifact/sec-option/report', payload);
      const resData = response.data;

      // DataResult 响应格式：{ code, msg, data }，code=200 表示业务成功
      if (resData?.code !== 200) {
        return { success: false, error: resData?.msg || 'Unknown error' };
      }

      const recordId = resData?.data?.recordId
        || resData?.data?.id
        || (typeof resData?.data === 'number' || typeof resData?.data === 'string' ? resData.data : null)
        || resData?.recordId
        || resData?.id;

      return { success: true, recordId: recordId };
    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        console.error(`Upload timeout after ${this.timeout}ms, URL: ${this.baseUrl}/build-artifact/sec-option/report`);
      } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        console.error(`Connection failed: ${error.code}, URL: ${this.baseUrl}/build-artifact/sec-option/report`);
      } else if (error.response) {
        console.error(`HTTP ${error.response.status}: ${JSON.stringify(error.response.data)}`);
      } else {
        console.error(`Upload error: ${error.code || error.message}, URL: ${this.baseUrl}/build-artifact/sec-option/report`);
      }
      const resData = error.response?.data;
      const errorMsg = resData?.msg || resData?.message || error.message;
      return { success: false, error: errorMsg };
    }
  }
}

module.exports = CicdUploader;
