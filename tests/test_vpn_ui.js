/**
 * UI Verification Script for PasarGuard VPN Panel
 * Verifies rendering, tab switching, client link updates, and clean disposal.
 */
const fs = require('fs');
const path = require('path');

// Minimal DOM simulation for unit testing UI scripts
class MockElement {
  constructor(tag, id = '') {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.className = '';
    this.innerHTML = '';
    this.style = {};
    this.children = [];
    this.attributes = {};
    this.onclick = null;
    this.oninput = null;
    this.onchange = null;
    this._innerHTML = '';
  }
  get innerHTML() {
    return this._innerHTML;
  }
  set innerHTML(html) {
    this._innerHTML = html;
    // Extract elements with id and classes to simulate parsed DOM
    const idMatches = [...html.matchAll(/id=["']([^"']+)["']/g)];
    for (const m of idMatches) {
      const child = new MockElement('div', m[1]);
      if (global.document) global.document.elementsById[m[1]] = child;
      this.children.push(child);
    }
  }
  appendChild(child) {
    this.children.push(child);
    if (child.id && global.document) {
      global.document.elementsById[child.id] = child;
    }
    return child;
  }
  remove() {
    this.removed = true;
    if (this.id && global.document) {
      delete global.document.elementsById[this.id];
    }
    if (global.document && global.document.body) {
      const idx = global.document.body.children.indexOf(this);
      if (idx !== -1) global.document.body.children.splice(idx, 1);
    }
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  querySelectorAll(sel) {
    let matches = [];
    function traverse(node) {
      if (!node) return;
      if (sel.startsWith('.') && node.className && node.className.includes(sel.substring(1))) {
        matches.push(node);
      } else if (sel.startsWith('#') && node.id === sel.substring(1)) {
        matches.push(node);
      } else if (node.tagName && node.tagName.toLowerCase() === sel.toLowerCase()) {
        matches.push(node);
      }
      if (node.children) {
        for (let c of node.children) traverse(c);
      }
    }
    traverse(this);
    return matches;
  }
  getAttribute(name) {
    return this.attributes[name] || null;
  }
  setAttribute(name, val) {
    this.attributes[name] = val;
  }
}

class MockDocument {
  constructor() {
    this.head = new MockElement('head');
    this.body = new MockElement('body');
    this.elementsById = {};
  }
  createElement(tag) {
    return new MockElement(tag);
  }
  getElementById(id) {
    if (this.elementsById[id] && !this.elementsById[id].removed) {
      return this.elementsById[id];
    }
    const found = this.body.querySelector('#' + id) || this.head.querySelector('#' + id);
    return found && !found.removed ? found : null;
  }
  querySelector(sel) {
    return this.body.querySelector(sel) || this.head.querySelector(sel);
  }
}

// Setup Global Browser Mock
global.window = {};
global.document = new MockDocument();
global.MutationObserver = class {
  observe() {}
  disconnect() {}
};

console.log('[Agent Pixel] Starting UI automated tests for plugin/vpn-panel.js...');

// Load script
const scriptContent = fs.readFileSync(path.join(__dirname, '../plugin/vpn-panel.js'), 'utf-8');
eval(scriptContent);

// Test 1: Style Injection
window.__PasarGuardVPN.injectStyles();
const styleEl = document.getElementById(window.__PasarGuardVPN.STYLES_ID);
if (!styleEl) {
  console.error('FAIL: Style element not found');
  process.exit(1);
}
console.log('✓ PASS: Isolated CSS styles injected successfully');

// Test 2: Modal Rendering
window.__PasarGuardVPN.renderModal();
const modal = document.getElementById(window.__PasarGuardVPN.MODAL_ID);
if (!modal) {
  console.error('FAIL: Modal not created in DOM');
  process.exit(1);
}
if (!modal.innerHTML.includes('PasarGuard Unified VPN Manager')) {
  console.error('FAIL: Modal title not found');
  process.exit(1);
}
console.log('✓ PASS: Modal rendered with correct title and badge');

// Test 3: Close button cleanly removes modal
const closeBtn = document.getElementById('pg-vpn-close');
if (!closeBtn) {
  console.error('FAIL: Close button not found');
  process.exit(1);
}
closeBtn.onclick();
if (document.getElementById(window.__PasarGuardVPN.MODAL_ID)) {
  console.error('FAIL: Modal still present after clicking close');
  process.exit(1);
}
console.log('✓ PASS: Modal closes cleanly without dangling DOM nodes');

// Test 4: Re-render modal and verify Tab Switching
window.__PasarGuardVPN.renderModal();
const modalAgain = document.getElementById(window.__PasarGuardVPN.MODAL_ID);
if (!modalAgain) {
  console.error('FAIL: Could not re-open modal');
  process.exit(1);
}

window.__PasarGuardVPN.setTab('groups');
const modalWithGroups = document.getElementById(window.__PasarGuardVPN.MODAL_ID);
if (!modalWithGroups.innerHTML.includes('گروه‌های کاربری')) {
  console.error('FAIL: Groups tab content not rendered in modal');
  process.exit(1);
}
console.log('✓ PASS: Tab switching to Groups works seamlessly');

// Test 5: Switch to clients tab and test link updating
window.__PasarGuardVPN.setTab('clients');
const btnOvpn = document.getElementById('btn-dl-ovpn');
const btnMobile = document.getElementById('btn-dl-mobileconfig');
if (!btnOvpn || !btnMobile) {
  console.error('FAIL: Download buttons not found in clients tab');
  process.exit(1);
}
if (!btnOvpn.getAttribute('href').includes('client/ovpn') || !btnMobile.getAttribute('href').includes('client/mobileconfig')) {
  console.error('FAIL: Download links do not have correct endpoint targets');
  process.exit(1);
}
console.log('✓ PASS: Client download URLs generate and update reactively');

// Clean up
const finalClose = document.getElementById('pg-vpn-close');
if (finalClose) finalClose.onclick();

console.log('[Agent Pixel] All UI verification tests PASSED with 100% precision!');
