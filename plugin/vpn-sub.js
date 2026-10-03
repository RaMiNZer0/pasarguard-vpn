/**
 * PasarGuard VPN Client Subscription Card & Auto-Injector
 * ========================================================
 * Automatically injects 1-Click Apple IKEv2 (.mobileconfig) and OpenVPN (.ovpn)
 * download buttons and connection credentials into the PasarGuard client subscription page.
 */
(() => {
  'use strict';

  if (window.__PG_VPN_SUB_INITIALIZED__) return;
  window.__PG_VPN_SUB_INITIALIZED__ = true;

  function initVPNSubscription() {
    // 1. Get username from window.__INITIAL_DATA__ or DOM
    let username = window.__INITIAL_DATA__?.user?.username;
    if (!username) {
      const match = document.title.match(/^([a-zA-Z0-9_\-\.]+)/);
      if (match) username = match[1];
    }
    if (!username) {
      // Try path or query
      const p = window.location.pathname;
      const parts = p.split('/');
      if (parts.length > 2 && parts[1] === 'sub') {
        // Wait briefly for app to load __INITIAL_DATA__
        setTimeout(initVPNSubscription, 800);
        return;
      }
    }
    if (!username) return;

    // 2. Fetch VPN subscription details from PasarGuard API
    fetch(`/api/vpn/subscription/${encodeURIComponent(username)}`)
      .then((res) => {
        if (!res.ok) throw new Error('VPN config not found');
        return res.json();
      })
      .then((data) => {
        if (!data || !data.configs || data.configs.length === 0) return;
        renderVPNSection(data);
      })
      .catch((err) => {
        console.warn('PasarGuard VPN subscription notice:', err);
      });
  }

  function copyToClipboard(text, btnElement) {
    if (!navigator.clipboard) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    } else {
      navigator.clipboard.writeText(text);
    }
    if (btnElement) {
      const orig = btnElement.innerHTML;
      btnElement.innerHTML = 'کپی شد ✓';
      btnElement.style.color = '#10b981';
      setTimeout(() => {
        btnElement.innerHTML = orig;
        btnElement.style.color = '';
      }, 2000);
    }
  }

  function renderVPNSection(data) {
    if (document.getElementById('pg-vpn-sub-container')) return;

    const styleId = 'pg-vpn-sub-styles';
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style');
      style.id = styleId;
      style.textContent = `
        .pg-vpn-box {
          direction: rtl;
          font-family: inherit, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Vazirmatn", sans-serif;
          margin: 20px auto;
          width: 100%;
          max-width: 800px;
          background: rgba(24, 24, 27, 0.85);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 18px;
          padding: 22px;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
          color: #f4f4f5;
          box-sizing: border-box;
        }
        .pg-vpn-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          padding-bottom: 14px;
          margin-bottom: 16px;
          flex-wrap: wrap;
          gap: 10px;
        }
        .pg-vpn-title {
          font-size: 16px;
          font-weight: 700;
          display: flex;
          align-items: center;
          gap: 10px;
          color: #f59e0b;
        }
        .pg-vpn-badge {
          font-size: 11px;
          background: rgba(245, 158, 11, 0.15);
          color: #fbbf24;
          border: 1px solid rgba(245, 158, 11, 0.3);
          border-radius: 6px;
          padding: 3px 8px;
          font-weight: 600;
        }
        .pg-vpn-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 14px;
        }
        .pg-vpn-node-card {
          background: rgba(39, 39, 42, 0.7);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 14px;
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 12px;
          transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .pg-vpn-node-card:hover {
          border-color: rgba(245, 158, 11, 0.4);
          transform: translateY(-2px);
        }
        .pg-vpn-node-title {
          font-size: 15px;
          font-weight: 600;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .pg-vpn-node-status {
          font-size: 11px;
          color: #10b981;
          display: flex;
          align-items: center;
          gap: 4px;
        }
        .pg-vpn-btn-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .pg-vpn-dl-btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          text-decoration: none;
          font-size: 13px;
          font-weight: 600;
          padding: 10px 14px;
          border-radius: 10px;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .pg-vpn-btn-apple {
          background: #2563eb;
          color: #ffffff !important;
          border: 1px solid #3b82f6;
        }
        .pg-vpn-btn-apple:hover {
          background: #1d4ed8;
        }
        .pg-vpn-btn-ovpn {
          background: #f59e0b;
          color: #000000 !important;
          border: 1px solid #d97706;
        }
        .pg-vpn-btn-ovpn:hover {
          background: #d97706;
        }
        .pg-vpn-creds {
          background: rgba(20, 20, 23, 0.8);
          border-radius: 10px;
          padding: 10px 12px;
          font-size: 12px;
          color: #d4d4d8;
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .pg-vpn-cred-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 2px 0;
        }
        .pg-vpn-copy-btn {
          background: rgba(255, 255, 255, 0.08);
          border: none;
          color: #a1a1aa;
          cursor: pointer;
          font-size: 11px;
          padding: 2px 8px;
          border-radius: 4px;
          transition: background 0.2s;
        }
        .pg-vpn-copy-btn:hover {
          background: rgba(255, 255, 255, 0.15);
          color: #ffffff;
        }
        .pg-vpn-help-hint {
          font-size: 11px;
          color: #71717a;
          margin-top: 14px;
          line-height: 1.6;
        }
      `;
      document.head.appendChild(style);
    }

    const container = document.createElement('div');
    container.id = 'pg-vpn-sub-container';
    container.className = 'pg-vpn-box';

    let cardsHtml = '';
    data.configs.forEach((cfg) => {
      const pw = cfg.credentials?.password || '';
      cardsHtml += `
        <div class="pg-vpn-node-card">
          <div class="pg-vpn-node-title">
            <span>${cfg.display_name || cfg.node}</span>
            <span class="pg-vpn-node-status">● آنلاین</span>
          </div>

          <div class="pg-vpn-btn-group">
            <a href="${cfg.ovpn_download_url}&proto=tcp" class="pg-vpn-dl-btn pg-vpn-btn-ovpn" style="background: #2563eb; color: #ffffff !important; border: 1px solid #1d4ed8; font-weight: bold;">
              <span>🛡️</span>
              <span>دانلود OpenVPN سبک میکروتیک (TCP 443 - ضد فیلتر)</span>
            </a>
            <a href="${cfg.mobileconfig_download_url}" class="pg-vpn-dl-btn pg-vpn-btn-apple">
              <span>🍏</span>
              <span>نصب مستقیم در آیفون / مک (IKEv2)</span>
            </a>
            <a href="${cfg.ovpn_download_url}&proto=udp" class="pg-vpn-dl-btn pg-vpn-btn-ovpn">
              <span>⚡</span>
              <span>دانلود OpenVPN (پروتکل UDP 1194)</span>
            </a>
          </div>

          <div class="pg-vpn-creds">
            <div class="pg-vpn-cred-row">
              <span style="color:#a1a1aa;">آدرس سرور (L2TP / IKEv2 / OpenVPN):</span>
              <span>
                <code>${cfg.server_host}</code>
                <button class="pg-vpn-copy-btn" data-copy="${cfg.server_host}">کپی</button>
              </span>
            </div>
            <div class="pg-vpn-cred-row">
              <span style="color:#a1a1aa;">نام کاربری:</span>
              <span>
                <code>${data.username}</code>
                <button class="pg-vpn-copy-btn" data-copy="${data.username}">کپی</button>
              </span>
            </div>
            <div class="pg-vpn-cred-row">
              <span style="color:#a1a1aa;">رمز عبور:</span>
              <span>
                <code>${pw ? pw.substring(0, 10) + '...' : '-'}</code>
                <button class="pg-vpn-copy-btn" data-copy="${pw}">کپی رمز</button>
              </span>
            </div>
            <div class="pg-vpn-cred-row">
              <span style="color:#a1a1aa;">کلید اشتراکی L2TP (Secret / PSK):</span>
              <span>
                <code>PasarGuardVPN123</code>
                <button class="pg-vpn-copy-btn" data-copy="PasarGuardVPN123">کپی سکرت</button>
              </span>
            </div>
          </div>
        </div>
      `;
    });

    container.innerHTML = `
      <div class="pg-vpn-header">
        <div class="pg-vpn-title">
          <span>🛡️ پروتکل‌های مستقیم VPN (سیستم‌عامل و OpenVPN)</span>
          <span class="pg-vpn-badge">IKEv2 & OpenVPN</span>
        </div>
        <div style="font-size:12px; color:#a1a1aa;">
          اتصال پرسرعت بدون قطعی به نودهای اختصاصی
        </div>
      </div>

      <div class="pg-vpn-grid">
        ${cardsHtml}
      </div>

      <div class="pg-vpn-help-hint">
        💡 <b>راهنمای اتصال سریع:</b><br>
        • <b>آیفون و آیپد:</b> دکمه آبی (نصب مستقیم) را بزنید؛ سپس در تنظیمات گوشی به Settings > Profile Downloaded رفته و دکمه Install را بزنید (بدون نیاز به پسورد وصل می‌شود).<br>
        • <b>اندروید و ویندوز:</b> فایل کانفیگ .ovpn را دانلود کرده و وارد نرم‌افزار <b>OpenVPN Connect</b> کنید و رمز عبور را وارد نمایید.
      </div>
    `;

    // Try to insert after the main subscription details card or at the end of the body
    const targetElement = document.querySelector('.subscription-info') ||
                          document.querySelector('#app') ||
                          document.querySelector('main') ||
                          document.body;

    if (targetElement === document.body) {
      document.body.appendChild(container);
    } else {
      targetElement.parentNode.insertBefore(container, targetElement.nextSibling);
    }

    // Attach copy button handlers
    container.querySelectorAll('.pg-vpn-copy-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const textToCopy = btn.getAttribute('data-copy');
        if (textToCopy) copyToClipboard(textToCopy, btn);
      });
    });
  }

  // Run when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVPNSubscription);
  } else {
    initVPNSubscription();
  }
})();
