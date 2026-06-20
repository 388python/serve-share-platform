// tea-server-platform - 前端主应用脚本
// 提供通用工具函数：API 请求、API key 管理、消息提示、表单辅助等

(function () {
  'use strict';

  // ============ 基础配置 ============
  const CONFIG = {
    API_BASE: window.__API_BASE__ || '/api/v1',
    STORAGE_KEY: 'tea_platform_api_key',
    DEBUG: true,
  };

  // ============ 日志工具 ============
  function log(...args) {
    if (CONFIG.DEBUG) {
      console.log('[tea-platform]', ...args);
    }
  }

  function logError(...args) {
    console.error('[tea-platform]', ...args);
  }

  // ============ API Key 管理 ============
  function getApiKey() {
    try {
      return localStorage.getItem(CONFIG.STORAGE_KEY) || '';
    } catch (e) {
      return '';
    }
  }

  function setApiKey(key) {
    try {
      localStorage.setItem(CONFIG.STORAGE_KEY, key || '');
      return true;
    } catch (e) {
      logError('Failed to save API key:', e);
      return false;
    }
  }

  function clearApiKey() {
    try {
      localStorage.removeItem(CONFIG.STORAGE_KEY);
    } catch (e) {
      // ignore
    }
  }

  // ============ API 请求工具 ============
  function buildUrl(path) {
    if (path.startsWith('http://') || path.startsWith('https://')) {
      return path;
    }
    const base = CONFIG.API_BASE.replace(/\/$/, '');
    const p = path.startsWith('/') ? path : '/' + path;
    return base + p;
  }

  async function apiRequest(path, options = {}) {
    const apiKey = getApiKey();
    const headers = Object.assign(
      {
        'Content-Type': 'application/json',
      },
      options.headers || {}
    );
    if (apiKey) {
      headers['Authorization'] = 'Bearer ' + apiKey;
    }

    const response = await fetch(buildUrl(path), Object.assign({}, options, { headers }));

    if (!response.ok) {
      let message = '请求失败';
      try {
        const errData = await response.json();
        if (errData && errData.message) message = errData.message;
        else if (errData && errData.error) message = errData.error;
      } catch (_) {
        // 非 JSON 响应
      }
      const err = new Error(message);
      err.status = response.status;
      throw err;
    }

    // 尝试解析 JSON，失败则返回文本
    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch (_) {
      return text;
    }
  }

  function apiGet(path) {
    return apiRequest(path, { method: 'GET' });
  }

  function apiPost(path, data) {
    return apiRequest(path, {
      method: 'POST',
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
  }

  function apiPut(path, data) {
    return apiRequest(path, {
      method: 'PUT',
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
  }

  function apiDelete(path) {
    return apiRequest(path, { method: 'DELETE' });
  }

  // ============ Toast 消息提示 ============
  function showToast(message, type, duration) {
    type = type || 'info';
    duration = duration || 3000;

    // 确保 toast 容器存在
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.style.cssText =
        'position:fixed;top:20px;right:20px;z-index:9999;pointer-events:none;';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const bgMap = {
      success: '#198754',
      error: '#dc3545',
      warning: '#ffc107',
      info: '#0dcaf0',
    };
    toast.style.cssText =
      'background:' +
      (bgMap[type] || bgMap.info) +
      ';color:#fff;padding:12px 20px;border-radius:4px;margin-bottom:8px;box-shadow:0 2px 8px rgba(0,0,0,0.15);pointer-events:auto;min-width:200px;animation:slideIn 0.3s ease-out;';
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(function () {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s';
      setTimeout(function () {
        toast.remove();
      }, 300);
    }, duration);
  }

  function toastSuccess(msg) { showToast(msg, 'success', 2000); }
  function toastError(msg) { showToast(msg, 'error', 4000); }
  function toastInfo(msg) { showToast(msg, 'info', 3000); }
  function toastWarning(msg) { showToast(msg, 'warning', 3000); }

  // ============ 复制到剪贴板 ============
  async function copyToClipboard(text, successMsg) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // 兼容旧浏览器
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      if (successMsg) toastSuccess(successMsg);
      return true;
    } catch (e) {
      toastError('复制失败');
      return false;
    }
  }

  // ============ 表单工具 ============
  function confirmAction(message) {
    return window.confirm(message || '确定执行此操作吗？');
  }

  function serializeForm(form) {
    const data = {};
    const formData = new FormData(form);
    for (const [key, value] of formData.entries()) {
      // 处理同名多个值（如复选框）
      if (data.hasOwnProperty(key)) {
        if (!Array.isArray(data[key])) {
          data[key] = [data[key]];
        }
        data[key].push(value);
      } else {
        data[key] = value;
      }
    }
    return data;
  }

  // ============ 数字格式化 ============
  function formatNumber(n, decimals) {
    decimals = decimals === undefined ? 2 : decimals;
    const num = Number(n);
    if (isNaN(num)) return '0';
    return num.toFixed(decimals);
  }

  function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      const pad = function (n) { return String(n).padStart(2, '0'); };
      return (
        d.getFullYear() +
        '-' + pad(d.getMonth() + 1) +
        '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) +
        ':' + pad(d.getMinutes())
      );
    } catch (_) {
      return dateStr;
    }
  }

  // ============ 表单验证 ============
  function validateRequired(value, fieldName) {
    if (!value || String(value).trim() === '') {
      toastError((fieldName || '此字段') + '不能为空');
      return false;
    }
    return true;
  }

  function validatePositiveNumber(value, fieldName) {
    const n = Number(value);
    if (isNaN(n) || n <= 0) {
      toastError((fieldName || '此字段') + '必须是正数');
      return false;
    }
    return true;
  }

  // ============ 页面自动初始化 ============
  function initPage() {
    // 自动处理 data-copy 属性：点击复制
    document.querySelectorAll('[data-copy]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.preventDefault();
        const text = el.getAttribute('data-copy');
        copyToClipboard(text, '已复制');
      });
    });

    // 自动处理 data-confirm 属性：点击前确认
    document.querySelectorAll('[data-confirm]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        const msg = el.getAttribute('data-confirm');
        if (!confirmAction(msg)) {
          e.preventDefault();
          return false;
        }
      });
    });

    // 自动处理带 data-api-key-save 元素：点击后保存 API key
    const apiKeyInput = document.querySelector('[data-api-key-input]');
    const apiKeySaveBtn = document.querySelector('[data-api-key-save]');
    if (apiKeyInput && apiKeySaveBtn) {
      apiKeyInput.value = getApiKey();
      apiKeySaveBtn.addEventListener('click', function () {
        if (setApiKey(apiKeyInput.value)) {
          toastSuccess('API Key 已保存');
        }
      });
    }

    log('Platform initialized');
  }

  // ============ 暴露到全局 ============
  window.TeaPlatform = {
    CONFIG: CONFIG,
    getApiKey: getApiKey,
    setApiKey: setApiKey,
    clearApiKey: clearApiKey,
    apiRequest: apiRequest,
    apiGet: apiGet,
    apiPost: apiPost,
    apiPut: apiPut,
    apiDelete: apiDelete,
    toast: showToast,
    toastSuccess: toastSuccess,
    toastError: toastError,
    toastInfo: toastInfo,
    toastWarning: toastWarning,
    copyToClipboard: copyToClipboard,
    confirm: confirmAction,
    serializeForm: serializeForm,
    formatNumber: formatNumber,
    formatDate: formatDate,
    validateRequired: validateRequired,
    validatePositiveNumber: validatePositiveNumber,
    log: log,
    logError: logError,
  };

  // 兼容旧代码：暴露全局 getApiKey
  window.getApiKey = getApiKey;

  // DOM 加载后初始化
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPage);
  } else {
    initPage();
  }
})();
