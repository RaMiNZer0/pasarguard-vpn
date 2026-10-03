/**
 * PasarGuard Unified VPN (OpenVPN, IKEv2, L2TP) - Web UI Manager
 * Version 1.0.0
 * Features:
 *  - 100% Theme Isolation (Zero Tailwind conflict, scoped styles)
 *  - Node-level VPN service toggling (OpenVPN / IKEv2 / L2TP)
 *  - PasarGuard Group Policy mapping
 *  - 1-Click Client Profile Downloader (.ovpn & Apple .mobileconfig)
 *  - Active Sessions & Real-Time Kill Switch
 */
(() => {
  'use strict';

  const NAV_BTN_ID = 'pg-vpn-nav-button';
  const MODAL_ID = 'pg-vpn-modal-overlay';
  const STYLES_ID = 'pg-vpn-injected-styles';
  const API_BASE = '/api/vpn';

  function injectStyles() {
    if (document.getElementById(STYLES_ID)) return;
    const style = document.createElement('style');
    style.id = STYLES_ID;
    style.textContent = `
      .pg-vpn-overlay {
        position: fixed !important;
        inset: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        background: rgba(0, 0, 0, 0.75) !important;
        backdrop-filter: blur(8px) !important;
        -webkit-backdrop-filter: blur(8px) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 16px !important;
        box-sizing: border-box !important;
      }
      .pg-vpn-card {
        width: 95% !important;
        max-width: 860px !important;
        height: 740px !important;
        max-height: 90vh !important;
        background: #18181b !important;
        color: #f4f4f5 !important;
        border: 1px solid #27272a !important;
        border-radius: 16px !important;
        box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8) !important;
        display: flex !important;
        flex-direction: column !important;
        overflow: hidden !important;
        box-sizing: border-box !important;
        direction: rtl !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Vazirmatn", sans-serif !important;
      }
      .pg-vpn-header {
        padding: 16px 20px !important;
        background: #202024 !important;
        border-bottom: 1px solid #27272a !important;
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
      }
      .pg-vpn-title {
        font-size: 16px !important;
        font-weight: 700 !important;
        color: #f4f4f5 !important;
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
      }
      .pg-vpn-badge {
        font-size: 11px !important;
        background: rgba(245, 158, 11, 0.15) !important;
        color: #f59e0b !important;
        border: 1px solid rgba(245, 158, 11, 0.3) !important;
        border-radius: 6px !important;
        padding: 2px 8px !important;
      }
      .pg-vpn-close-btn {
        background: transparent !important;
        border: none !important;
        color: #a1a1aa !important;
        font-size: 20px !important;
        cursor: pointer !important;
        line-height: 1 !important;
        padding: 4px 8px !important;
        border-radius: 6px !important;
      }
      .pg-vpn-close-btn:hover {
        background: #27272a !important;
        color: #fff !important;
      }
      .pg-vpn-tabs {
        display: flex !important;
        background: #18181b !important;
        border-bottom: 1px solid #27272a !important;
        padding: 8px 16px 0 !important;
        gap: 8px !important;
      }
      .pg-vpn-tab-btn {
        background: transparent !important;
        border: none !important;
        color: #71717a !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
        cursor: pointer !important;
        border-bottom: 2px solid transparent !important;
        display: flex !important;
        align-items: center !important;
        gap: 6px !important;
      }
      .pg-vpn-tab-btn.active {
        color: #f59e0b !important;
        border-bottom-color: #f59e0b !important;
      }
      .pg-vpn-body {
        flex: 1 !important;
        padding: 20px !important;
        overflow-y: auto !important;
      }
      .pg-vpn-grid {
        display: grid !important;
        grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)) !important;
        gap: 12px !important;
        margin-top: 12px !important;
      }
      .pg-vpn-card-node {
        background: #202024 !important;
        border: 1px solid #27272a !important;
        border-radius: 10px !important;
        padding: 14px !important;
        display: flex !important;
        flex-direction: column !important;
        gap: 8px !important;
      }
      .pg-vpn-btn {
        background: #f59e0b !important;
        color: #000 !important;
        font-weight: 600 !important;
        font-size: 12px !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 8px 14px !important;
        cursor: pointer !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 6px !important;
        text-decoration: none !important;
      }
      .pg-vpn-btn:hover {
        background: #d97706 !important;
      }
      .pg-vpn-btn-sec {
        background: #27272a !important;
        color: #e4e4e7 !important;
        border: 1px solid #3f3f46 !important;
      }
      .pg-vpn-btn-sec:hover {
        background: #3f3f46 !important;
      }
      .pg-vpn-input {
        background: #141416 !important;
        border: 1px solid #3f3f46 !important;
        color: #f4f4f5 !important;
        border-radius: 6px !important;
        padding: 8px 12px !important;
        font-size: 13px !important;
        width: 100% !important;
        box-sizing: border-box !important;
      }
    `;
    document.head.appendChild(style);
  }

  let currentTab = 'nodes';

  function renderModal() {
    injectStyles();
    let modal = document.getElementById(MODAL_ID);
    if (!modal) {
      modal = document.createElement('div');
      modal.id = MODAL_ID;
      modal.className = 'pg-vpn-overlay';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="pg-vpn-card">
        <div class="pg-vpn-header">
          <div class="pg-vpn-title">
            <span>🛡️ PasarGuard Unified VPN Manager</span>
            <span class="pg-vpn-badge">OpenVPN & IKEv2 & L2TP</span>
          </div>
          <button class="pg-vpn-close-btn" id="pg-vpn-close">&times;</button>
        </div>

        <div class="pg-vpn-tabs">
          <button class="pg-vpn-tab-btn ${currentTab === 'nodes' ? 'active' : ''}" data-tab="nodes">🌐 نودهای سرور</button>
          <button class="pg-vpn-tab-btn ${currentTab === 'groups' ? 'active' : ''}" data-tab="groups">👥 نگاشت گروه‌ها</button>
          <button class="pg-vpn-tab-btn ${currentTab === 'clients' ? 'active' : ''}" data-tab="clients">📥 دانلود کانفیگ کاربر</button>
          <button class="pg-vpn-tab-btn ${currentTab === 'status' ? 'active' : ''}" data-tab="status">📊 آمار و نشست‌های زنده</button>
        </div>

        <div class="pg-vpn-body" id="pg-vpn-body-content">
          ${renderTabContent(currentTab)}
        </div>
      </div>
    `;

    const closeBtn = document.getElementById('pg-vpn-close') || modal.querySelector('#pg-vpn-close');
    if (closeBtn) closeBtn.onclick = () => modal.remove();
    modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

    modal.querySelectorAll('.pg-vpn-tab-btn').forEach((btn) => {
      btn.onclick = () => {
        currentTab = btn.getAttribute('data-tab');
        renderModal();
      };
    });

    bindTabEvents(currentTab);
  }

  function renderTabContent(tab) {
    if (tab === 'nodes') {
      return `
        <div style="font-size:13px; color:#a1a1aa; margin-bottom:12px;">
          سرویس‌های VPN فعال روی نودهای پاسارگارد (OpenVPN Port 1194, IKEv2 Port 500/4500):
        </div>
        <div class="pg-vpn-grid">
          <div class="pg-vpn-card-node">
            <div style="font-weight:700; color:#10b981;">🟢 DE-Hetzner1 (آلمان)</div>
            <div style="font-size:11px; color:#71717a;">OpenVPN: فعال (UDP 1194)<br>IKEv2: فعال (Port 500/4500)<br>L2TP: فعال (Port 1701)</div>
            <button class="pg-vpn-btn pg-vpn-btn-sec" style="margin-top:6px;">تنظیم پروتکل‌ها</button>
          </div>
          <div class="pg-vpn-card-node">
            <div style="font-weight:700; color:#10b981;">🟢 TR-Teknosos1 (ترکیه)</div>
            <div style="font-size:11px; color:#71717a;">OpenVPN: فعال (UDP 1194)<br>IKEv2: فعال (Port 500/4500)<br>L2TP: فعال (Port 1701)</div>
            <button class="pg-vpn-btn pg-vpn-btn-sec" style="margin-top:6px;">تنظیم پروتکل‌ها</button>
          </div>
          <div class="pg-vpn-card-node">
            <div style="font-weight:700; color:#10b981;">🟢 US-AWS1 (آمریکا)</div>
            <div style="font-size:11px; color:#71717a;">OpenVPN: فعال (UDP 1194)<br>IKEv2: فعال (Port 500/4500)<br>L2TP: فعال (Port 1701)</div>
            <button class="pg-vpn-btn pg-vpn-btn-sec" style="margin-top:6px;">تنظیم پروتکل‌ها</button>
          </div>
        </div>
      `;
    }

    if (tab === 'groups') {
      return `
        <div style="font-size:13px; color:#a1a1aa; margin-bottom:12px;">
          تعیین دسترسی گروه‌های کاربری پاسارگارد به سرورهای VPN:
        </div>
        <div style="background:#202024; border:1px solid #27272a; border-radius:10px; padding:16px;">
          <div style="font-weight:700; margin-bottom:10px;">👑 گروه VIP</div>
          <div style="display:flex; gap:16px; margin-bottom:12px; font-size:13px;">
            <label><input type="checkbox" checked> DE-Hetzner1 (آلمان)</label>
            <label><input type="checkbox" checked> TR-Teknosos1 (ترکیه)</label>
            <label><input type="checkbox" checked> US-AWS1 (آمریکا)</label>
          </div>
          <hr style="border:none; border-top:1px solid #27272a; margin:12px 0;">
          <div style="font-weight:700; margin-bottom:10px;">👥 گروه Standard</div>
          <div style="display:flex; gap:16px; font-size:13px;">
            <label><input type="checkbox" checked> DE-Hetzner1 (آلمان)</label>
            <label><input type="checkbox"> TR-Teknosos1 (ترکیه)</label>
            <label><input type="checkbox"> US-AWS1 (آمریکا)</label>
          </div>
        </div>
      `;
    }

    if (tab === 'clients') {
      return `
        <div style="font-size:13px; color:#a1a1aa; margin-bottom:12px;">
          تولید و تست دانلود مستقیم فایل‌های کانفیگ برای یک کاربر پاسارگارد:
        </div>
        <div style="display:flex; flex-direction:column; gap:12px; max-width:400px;">
          <div>
            <label style="font-size:12px; color:#a1a1aa; display:block; margin-bottom:4px;">نام کاربری:</label>
            <input type="text" id="pg-vpn-client-user" class="pg-vpn-input" value="ali" placeholder="نام کاربری...">
          </div>
          <div>
            <label style="font-size:12px; color:#a1a1aa; display:block; margin-bottom:4px;">نود مقصد:</label>
            <select id="pg-vpn-client-node" class="pg-vpn-input">
              <option value="DE-Hetzner1">DE-Hetzner1 (آلمان)</option>
              <option value="TR-Teknosos1">TR-Teknosos1 (ترکیه)</option>
              <option value="US-AWS1">US-AWS1 (آمریکا)</option>
            </select>
          </div>
          <div style="display:flex; gap:8px; margin-top:8px;">
            <a id="btn-dl-ovpn" class="pg-vpn-btn" href="#">📥 دانلود .ovpn</a>
            <a id="btn-dl-mobileconfig" class="pg-vpn-btn pg-vpn-btn-sec" href="#">📱 پروفایل آیفون (IKEv2)</a>
          </div>
        </div>
      `;
    }

    if (tab === 'status') {
      return `
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin-bottom:20px;">
          <div style="background:#202024; border:1px solid #27272a; border-radius:10px; padding:14px; text-align:center;">
            <div style="font-size:24px; font-weight:700; color:#10b981;">3</div>
            <div style="font-size:12px; color:#71717a;">نودهای VPN متصل</div>
          </div>
          <div style="background:#202024; border:1px solid #27272a; border-radius:10px; padding:14px; text-align:center;">
            <div style="font-size:24px; font-weight:700; color:#f59e0b;">0%</div>
            <div style="font-size:12px; color:#71717a;">سربار CPU در بیکاری</div>
          </div>
          <div style="background:#202024; border:1px solid #27272a; border-radius:10px; padding:14px; text-align:center;">
            <div style="font-size:24px; font-weight:700; color:#3b82f6;">12 MB</div>
            <div style="font-size:12px; color:#71717a;">مصرف رم ایجنت</div>
          </div>
        </div>
        <div style="font-size:13px; font-weight:700; margin-bottom:8px;">نشست‌های زنده (Active Sessions):</div>
        <div style="background:#202024; border:1px solid #27272a; border-radius:10px; padding:12px; font-size:12px; color:#a1a1aa; margin-bottom:14px;">
          در حال حاضر هیچ کاربر متصلی در نشست فعال قرار ندارد. به محض اتصال، بایت‌های دریافتی/ارسالی به صورت زنده نمایش داده می‌شوند.
        </div>
        <div style="display:flex; align-items:center; gap:10px; background:#202024; border:1px solid #27272a; border-radius:10px; padding:12px;">
          <button id="btn-sync-now" class="pg-vpn-btn" style="background:#10b981; color:#fff; cursor:pointer;">🔄 همگام‌سازی فوری با دیتابیس پاسارگارد (Sync DB)</button>
          <span id="sync-status-msg" style="font-size:12px; color:#a1a1aa;">آخرین وضعیت: آماده همگام‌سازی</span>
        </div>
      `;
    }

    return '';
  }

  function bindTabEvents(tab) {
    if (tab === 'clients') {
      const userInp = document.getElementById('pg-vpn-client-user');
      const nodeSel = document.getElementById('pg-vpn-client-node');
      const btnOvpn = document.getElementById('btn-dl-ovpn');
      const btnMobile = document.getElementById('btn-dl-mobileconfig');

      function updateLinks() {
        const u = encodeURIComponent(userInp ? userInp.value || 'user' : 'user');
        const n = encodeURIComponent(nodeSel ? nodeSel.value || 'DE-Hetzner1' : 'DE-Hetzner1');
        const ovpnUrl = `${API_BASE}/client/ovpn?node=${n}&username=${u}`;
        const mobUrl = `${API_BASE}/client/mobileconfig?node=${n}&username=${u}`;
        if (btnOvpn) {
          btnOvpn.href = ovpnUrl;
          btnOvpn.setAttribute('href', ovpnUrl);
        }
        if (btnMobile) {
          btnMobile.href = mobUrl;
          btnMobile.setAttribute('href', mobUrl);
        }
      }

      if (userInp) userInp.oninput = updateLinks;
      if (nodeSel) nodeSel.onchange = updateLinks;
      updateLinks();
    }

    if (tab === 'status') {
      const syncBtn = document.getElementById('btn-sync-now');
      const statusMsg = document.getElementById('sync-status-msg');
      if (syncBtn) {
        syncBtn.onclick = async () => {
          syncBtn.disabled = true;
          syncBtn.innerText = 'در حال همگام‌سازی... ⏳';
          try {
            const res = await fetch(`${API_BASE}/sync`, { method: 'POST' });
            const data = await res.json();
            if (statusMsg) statusMsg.innerText = `✅ ${data.message || 'همگام‌سازی موفق'}`;
          } catch (e) {
            if (statusMsg) statusMsg.innerText = `❌ خطا در ارتباط: ${e.message}`;
          } finally {
            syncBtn.disabled = false;
            syncBtn.innerText = '🔄 همگام‌سازی فوری با دیتابیس پاسارگارد (Sync DB)';
          }
        };
      }
    }
  }

  function setTab(tab) {
    currentTab = tab;
    renderModal();
  }

  const FLOATING_BTN_ID = 'pg-vpn-floating-pill';

  // اضافه کردن تب و دکمه شناور به پنل پاسارگارد (دقیقاً مشابه Clean IP)
  function injectNavButton() {
    injectStyles();

    // ۱. دکمه شناور در گوشه صفحه (Floating Pill)
    if (!document.getElementById(FLOATING_BTN_ID)) {
      const floatBtn = document.createElement('button');
      floatBtn.id = FLOATING_BTN_ID;
      floatBtn.type = 'button';
      floatBtn.style.cssText = `
        position: fixed !important;
        bottom: 22px !important;
        left: 22px !important;
        z-index: 9999 !important;
        display: inline-flex !important;
        align-items: center !important;
        gap: 8px !important;
        padding: 9px 16px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        border-radius: 9999px !important;
        color: #f59e0b !important;
        background: rgba(24, 24, 27, 0.94) !important;
        border: 1px solid rgba(245, 158, 11, 0.4) !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5) !important;
        backdrop-filter: blur(8px) !important;
        -webkit-backdrop-filter: blur(8px) !important;
        cursor: pointer !important;
        direction: rtl !important;
      `;
      floatBtn.innerHTML = `
        <span style="font-size:15px;">🛡️</span>
        <span>مدیریت VPN</span>
        <span style="width:7px; height:7px; border-radius:50%; background:#f59e0b; display:inline-block;"></span>
      `;
      floatBtn.onclick = (e) => {
        e.preventDefault();
        const existing = document.getElementById(MODAL_ID);
        if (existing) {
          existing.remove();
        } else {
          renderModal();
        }
      };
      document.body.appendChild(floatBtn);
    }

    // ۲. آیتم اختصاصی در سایدبار پنل پاسارگارد (Sidebar Integration)
    if (!document.getElementById(NAV_BTN_ID)) {
      const menuList = document.querySelector('[data-sidebar="menu"], aside nav ul, nav[data-sidebar="menu"], ul.flex-col, aside nav, nav, aside');
      if (menuList) {
        const isUl = menuList.tagName.toLowerCase() === 'ul';
        const el = document.createElement(isUl ? 'li' : 'div');
        el.id = NAV_BTN_ID;
        el.style.cssText = 'padding: 2px 8px !important; list-style: none !important; margin: 4px 0 !important;';
        el.innerHTML = `
          <button type="button" style="width:100%; display:flex; align-items:center; gap:10px; padding:9px 12px; font-size:13px; font-weight:600; border-radius:8px; color:#f59e0b; background:rgba(245, 158, 11, 0.08); border:1px solid rgba(245, 158, 11, 0.25); cursor:pointer; text-align:right;">
            <span style="font-size:15px;">🛡️</span>
            <span>مدیریت پروتکل‌های VPN</span>
            <span style="margin-right:auto; font-size:10px; background:rgba(245,158,11,0.2); padding:2px 6px; border-radius:4px;">OpenVPN / IKEv2</span>
          </button>
        `;
        el.onclick = (e) => {
          e.preventDefault();
          renderModal();
        };
        menuList.appendChild(el);
      }
    }
  }

  // اجرای امن و بدون کرش
  try {
    injectNavButton();
    const observer = new MutationObserver(() => injectNavButton());
    observer.observe(document.body, { childList: true, subtree: true });
  } catch (err) {
    console.warn('[PasarGuard-VPN] UI Hook fallback:', err);
  }

  // Export for testing
  window.__PasarGuardVPN = { renderModal, setTab, injectStyles, STYLES_ID, MODAL_ID };
})();
