'use strict';
'require baseclass';

return baseclass.extend({
    css: '\
    /* NYM VPN - Dark Theme */\
    :root {\
        --nym-green: #00ff94;\
        --nym-green-dim: rgba(0, 255, 148, 0.15);\
        --nym-green-glow: rgba(0, 255, 148, 0.4);\
        --bg-primary: #121218;\
        --bg-secondary: #1a1a24;\
        --bg-card: #1e1e2a;\
        --bg-card-hover: #252532;\
        --bg-input: #0d0d12;\
        --border-color: #2a2a3a;\
        --border-accent: #3a3a4a;\
        --text-primary: #e8e8ec;\
        --text-secondary: #9090a0;\
        --text-muted: #606070;\
        --danger: #ff4757;\
        --danger-dim: rgba(255, 71, 87, 0.15);\
        --warning: #ffa502;\
        --warning-dim: rgba(255, 165, 2, 0.15);\
    }\
    #view { background: var(--bg-primary) !important; min-height: 100vh; padding: 0 !important; }\
    .nym-container { background: var(--bg-primary); color: var(--text-primary); font-family: "SF Mono", "Fira Code", "JetBrains Mono", "Consolas", monospace; padding: 24px; max-width: 900px; margin: 0 auto; }\
    .nym-header { text-align: center; padding: 32px 0 40px; border-bottom: 1px solid var(--border-color); margin-bottom: 32px; }\
    .nym-logo { display: flex; justify-content: center; margin-bottom: 16px; }\
    .nym-logo svg { height: 40px; width: auto; fill: var(--nym-green); }\
    .nym-subtitle { color: var(--text-muted); font-size: 13px; margin-top: 12px; font-weight: 400; }\
    .nym-status-hero { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 48px 32px; text-align: center; margin-bottom: 24px; position: relative; overflow: hidden; }\
    .nym-status-hero::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, var(--nym-green), transparent); opacity: 0; transition: opacity 0.5s; }\
    .nym-status-hero.connected::before { opacity: 1; }\
    .nym-status-ring { width: 160px; height: 160px; margin: 0 auto 32px; position: relative; }\
    .nym-status-ring-outer { width: 100%; height: 100%; border-radius: 50%; border: 2px solid var(--border-color); position: absolute; top: 0; left: 0; transition: all 0.5s ease; }\
    .nym-status-ring-inner { width: 140px; height: 140px; border-radius: 50%; background: var(--bg-secondary); position: absolute; top: 10px; left: 10px; display: flex; align-items: center; justify-content: center; flex-direction: column; transition: all 0.5s ease; }\
    .nym-status-ring-pulse { width: 100%; height: 100%; border-radius: 50%; position: absolute; top: 0; left: 0; border: 2px solid transparent; animation: none; }\
    .nym-status-hero.connected .nym-status-ring-outer { border-color: var(--nym-green); box-shadow: 0 0 30px var(--nym-green-glow), inset 0 0 20px var(--nym-green-dim); }\
    .nym-status-hero.connected .nym-status-ring-pulse { border-color: var(--nym-green); animation: pulse-ring 2s ease-out infinite; }\
    .nym-status-hero.connected .nym-status-ring-inner { background: var(--nym-green-dim); }\
    .nym-status-hero.connecting .nym-status-ring-outer, .nym-status-hero.disconnecting .nym-status-ring-outer { border-color: var(--warning); border-width: 3px; animation: rotate-ring 4s linear infinite; border-style: dashed; }\
    .nym-status-hero.connecting .nym-status-ring-inner, .nym-status-hero.disconnecting .nym-status-ring-inner { background: var(--warning-dim); }\
    .nym-status-hero.disconnected .nym-status-ring-outer { border-color: var(--text-muted); }\
    @keyframes pulse-ring { 0% { transform: scale(1); opacity: 1; } 100% { transform: scale(1.3); opacity: 0; } }\
    @keyframes rotate-ring { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }\
    .nym-status-label { font-size: 13px; text-transform: uppercase; letter-spacing: 2px; color: var(--text-secondary); font-weight: 500; text-align: center; }\
    .nym-status-hero.connected .nym-status-label { color: var(--nym-green); }\
    .nym-status-hero.connecting .nym-status-label, .nym-status-hero.disconnecting .nym-status-label { color: var(--warning); }\
    .nym-uptime { font-size: 28px; font-weight: 300; color: var(--text-primary); margin-bottom: 8px; font-variant-numeric: tabular-nums; }\
    .nym-uptime-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }\
    .nym-gateway-display { display: flex; justify-content: space-between; align-items: flex-start; margin-top: 32px; padding-top: 24px; border-top: 1px solid var(--border-color); }\
    .nym-gateway-item { display: flex; flex-direction: column; align-items: center; flex: 1; max-width: 280px; }\
    .nym-gateway-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; text-indent: 2px; color: var(--text-muted); margin-bottom: 8px; text-align: center; }\
    .nym-connection-wrapper { display: flex; flex-direction: column; align-items: center; justify-content: center; padding-top: 20px; opacity: 0; transform: scale(0.95); transition: opacity 0.5s ease, transform 0.5s ease; pointer-events: none; }\
    .nym-status-hero.connected .nym-connection-wrapper, .nym-status-hero.disconnecting .nym-connection-wrapper { opacity: 1; transform: scale(1); pointer-events: auto; }\
    .nym-mode-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: var(--nym-green); opacity: 0.8; margin-bottom: 8px; }\
    .nym-connection-chain { display: flex; align-items: center; justify-content: center; padding-top: 0; gap: 0; margin: 0 -12px; }\
    .nym-chain-node { width: 14px; height: 14px; border-radius: 50%; background: var(--nym-green); opacity: 0.8; flex-shrink: 0; box-shadow: 0 0 6px var(--nym-green-glow); }\
    .nym-chain-line { width: 24px; height: 2px; background: repeating-linear-gradient(90deg, var(--nym-green) 0px, var(--nym-green) 3px, transparent 3px, transparent 6px); background-size: 200% 100%; opacity: 0.5; animation: chain-flow 4s linear infinite; }\
    .nym-chain-node.mixnet { width: 12px; height: 12px; opacity: 0.6; }\
    .nym-chain-line.long { width: 126px; }\
    @keyframes chain-flow { 0% { background-position: 100% 0; } 100% { background-position: 0% 0; } }\
    .nym-gateway-value { display: flex; flex-direction: column; align-items: center; gap: 4px; }\
    .nym-gateway-flag { font-size: 28px; line-height: 1; min-width: 36px; text-align: center; }\
    .nym-gateway-name { font-size: 12px; color: var(--text-primary); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\
    .nym-gateway-id { font-size: 9px; color: var(--text-secondary); font-family: monospace; max-width: 260px; }\
    .nym-gateway-ip { font-size: 10px; color: var(--text-muted); font-family: monospace; }\
    .nym-gateway-empty { font-size: 24px; color: var(--text-muted); }\
    .nym-action-buttons { display: flex; justify-content: center; gap: 16px; margin-top: 32px; }\
    .nym-btn { padding: 14px 40px; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s ease; font-family: inherit; outline: none !important; box-shadow: none; }\
    .nym-btn:focus, .nym-btn:active { outline: none !important; box-shadow: none !important; }\
    .nym-btn:disabled { opacity: 0.4; cursor: not-allowed; }\
    .nym-btn-primary { background: var(--nym-green) !important; color: var(--bg-primary) !important; }\
    .nym-btn-primary:hover:not(:disabled) { background: #00e085 !important; box-shadow: 0 0 24px var(--nym-green-glow) !important; transform: translateY(-1px); }\
    .nym-btn-primary:focus:not(:disabled) { background: var(--nym-green) !important; box-shadow: none !important; }\
    .nym-btn-primary:active:not(:disabled) { transform: translateY(0); }\
    .nym-btn-danger { background: transparent !important; color: var(--danger) !important; border: 1px solid var(--danger) !important; }\
    .nym-btn-danger:hover:not(:disabled) { background: var(--danger-dim) !important; box-shadow: 0 0 24px var(--danger-dim) !important; transform: translateY(-1px); }\
    .nym-btn-danger:focus:not(:disabled) { background: transparent !important; box-shadow: none !important; }\
    .nym-btn-danger:active:not(:disabled) { background: var(--danger-dim) !important; transform: translateY(0); }\
    .nym-btn-secondary { background: transparent; color: var(--text-secondary); border: 1px solid var(--border-color); }\
    .nym-btn-secondary:hover:not(:disabled) { border-color: var(--text-secondary); color: var(--text-primary); }\
    .nym-btn-small { padding: 8px 16px; font-size: 11px; }\
    .nym-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; margin-bottom: 16px; overflow: hidden; }\
    .nym-card-header { padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: background 0.2s; user-select: none; }\
    .nym-card-header:hover { background: var(--bg-card-hover); }\
    .nym-card-title { display: flex; align-items: center; gap: 12px; font-size: 14px; font-weight: 500; color: var(--text-primary); }\
    .nym-card-icon { width: 32px; height: 32px; background: var(--nym-green-dim); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; }\
    .nym-card-chevron { color: var(--text-muted); transition: transform 0.3s ease; font-size: 12px; }\
    .nym-card.expanded .nym-card-chevron { transform: rotate(180deg); }\
    .nym-card-body { padding: 0 20px 20px; display: none; }\
    .nym-card.expanded .nym-card-body { display: block; animation: slideDown 0.3s ease; }\
    @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }\
    .nym-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.85); display: flex; align-items: center; justify-content: center; z-index: 10000; backdrop-filter: blur(4px); animation: modalFadeIn 0.3s ease; }\
    .nym-modal-overlay.fade-out { animation: modalFadeOut 0.5s ease forwards; }\
    @keyframes modalFadeIn { from { opacity: 0; } to { opacity: 1; } }\
    @keyframes modalFadeOut { from { opacity: 1; } to { opacity: 0; } }\
    .nym-modal { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 40px; text-align: center; max-width: 320px; width: 90%; }\
    .nym-modal-ring { width: 120px; height: 120px; margin: 0 auto 24px; position: relative; }\
    .nym-modal-ring-outer { width: 100%; height: 100%; border-radius: 50%; border: 3px dashed var(--warning); animation: rotate-ring 2s linear infinite; position: absolute; transition: all 0.3s ease; }\
    .nym-modal-ring-inner { width: 100px; height: 100px; border-radius: 50%; background: var(--warning-dim); position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); display: flex; align-items: center; justify-content: center; transition: all 0.3s ease; }\
    .nym-modal-overlay.success .nym-modal-ring-outer { border: 3px solid var(--nym-green); border-style: solid; animation: none; box-shadow: 0 0 30px var(--nym-green-glow); }\
    .nym-modal-overlay.success .nym-modal-ring-inner { background: var(--nym-green-dim); }\
    .nym-modal-overlay.success .nym-modal-icon { color: var(--nym-green); }\
    .nym-modal-icon { font-size: 32px; transition: color 0.3s ease; }\
    .nym-modal-ring-static { animation: none !important; border-style: solid !important; }\
    .nym-modal-title { color: var(--text-primary); font-size: 18px; font-weight: 600; margin-bottom: 8px; }\
    .nym-modal-message { color: var(--text-muted); font-size: 13px; line-height: 1.5; }\
    .nym-modal-buttons { display: flex; gap: 12px; justify-content: center; margin-top: 24px; }\
    .nym-modal-buttons .nym-btn { padding: 10px 24px; font-size: 12px; min-width: 100px; white-space: nowrap; }\
    .nym-modal-buttons .nym-btn-danger { background: transparent !important; background-color: transparent !important; background-image: none !important; color: var(--danger) !important; border: 1px solid var(--danger) !important; }\
    .nym-modal-buttons .nym-btn-danger:hover { background: var(--danger-dim) !important; background-color: var(--danger-dim) !important; box-shadow: 0 0 24px var(--danger-dim) !important; }\
    .nym-modal-buttons .nym-btn-primary { background: var(--nym-green) !important; background-color: var(--nym-green) !important; background-image: none !important; color: var(--bg-primary) !important; }\
    .nym-modal-buttons .nym-btn-primary:hover { background: #00e085 !important; background-color: #00e085 !important; box-shadow: 0 0 24px var(--nym-green-glow) !important; }\
    .nym-toast-container { position: fixed; top: 20px; right: 20px; z-index: 10001; display: flex; flex-direction: column; gap: 10px; max-width: 360px; }\
    .nym-toast { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; gap: 12px; animation: slideIn 0.3s ease; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4); }\
    .nym-toast.success { border-left: 3px solid var(--nym-green); }\
    .nym-toast.error { border-left: 3px solid var(--danger); }\
    .nym-toast.warning { border-left: 3px solid var(--warning); }\
    .nym-toast-icon { font-size: 18px; flex-shrink: 0; }\
    .nym-toast.success .nym-toast-icon { color: var(--nym-green); }\
    .nym-toast.error .nym-toast-icon { color: var(--danger); }\
    .nym-toast.warning .nym-toast-icon { color: var(--warning); }\
    .nym-toast-message { color: var(--text-primary); font-size: 13px; flex: 1; }\
    .nym-toast-close { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px; font-size: 16px; }\
    .nym-toast-close:hover { color: var(--text-primary); }\
    @keyframes slideIn { from { opacity: 0; transform: translateX(100px); } to { opacity: 1; transform: translateX(0); } }\
    @keyframes slideOut { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(100px); } }\
    .nym-card-description { color: var(--text-muted); font-size: 12px; margin-bottom: 20px; line-height: 1.6; }\
    .nym-form-group { margin-bottom: 20px; }\
    .nym-form-label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-secondary); margin-bottom: 8px; }\
    .nym-select { width: 100%; padding: 12px 16px; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 14px; font-family: inherit; cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'12\' viewBox=\'0 0 12 12\'%3E%3Cpath fill=\'%23606070\' d=\'M6 8L1 3h10z\'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 16px center; transition: border-color 0.2s, box-shadow 0.2s; }\
    .nym-select:hover { border-color: var(--border-accent); }\
    .nym-select:focus { outline: none; border-color: var(--nym-green); box-shadow: 0 0 0 3px var(--nym-green-dim); }\
    .nym-input { width: 100%; padding: 12px 16px; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 14px; font-family: inherit; transition: border-color 0.2s, box-shadow 0.2s; }\
    .nym-input::placeholder { color: var(--text-muted); }\
    .nym-input:focus { outline: none; border-color: var(--nym-green); box-shadow: 0 0 0 3px var(--nym-green-dim); }\
    .nym-toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid var(--border-color); }\
    .nym-toggle-row:last-child { border-bottom: none; }\
    .nym-toggle-info { flex: 1; }\
    .nym-toggle-title { font-size: 14px; color: var(--text-primary); margin-bottom: 4px; }\
    .nym-toggle-desc { font-size: 12px; color: var(--text-muted); }\
    .nym-toggle { position: relative; width: 48px; height: 26px; flex-shrink: 0; margin-left: 16px; }\
    .nym-toggle input { opacity: 0; width: 0; height: 0; }\
    .nym-toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 26px; transition: all 0.3s ease; }\
    .nym-toggle-slider::before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background: var(--text-muted); border-radius: 50%; transition: all 0.3s ease; }\
    .nym-toggle input:checked + .nym-toggle-slider { background: var(--nym-green-dim); border-color: var(--nym-green); }\
    .nym-toggle input:checked + .nym-toggle-slider::before { transform: translateX(22px); background: var(--nym-green); }\
    .nym-gateway-section { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }\
    @media (max-width: 600px) { .nym-gateway-section { grid-template-columns: 1fr; } }\
    .nym-gateway-box { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }\
    .nym-gateway-box-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--nym-green); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }\
    .nym-gateway-box-title::before { content: ""; width: 6px; height: 6px; background: var(--nym-green); border-radius: 50%; }\
    .nym-gateway-loading { color: var(--text-muted); font-size: 13px; font-style: italic; padding: 12px 0; }\
    .nym-gateway-option { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 6px; margin-bottom: 6px; cursor: pointer; transition: all 0.2s; }\
    .nym-gateway-option:hover { border-color: var(--nym-green); background: var(--bg-card-hover); }\
    .nym-gateway-option.selected { border-color: var(--nym-green); background: var(--nym-green-dim); }\
    .nym-gateway-option input[type="radio"] { display: none; }\
    .nym-gateway-option-icon { width: 24px; height: 24px; flex-shrink: 0; }\
    .nym-gateway-option-icon svg { width: 100%; height: 100%; }\
    .nym-gateway-option-info { flex: 1; min-width: 0; }\
    .nym-gateway-option-name { font-size: 13px; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\
    .nym-gateway-option-perf { font-size: 11px; color: var(--text-muted); }\
    .nym-gateway-list { max-height: 200px; overflow-y: auto; }\
    .nym-gateway-list::-webkit-scrollbar { width: 4px; }\
    .nym-gateway-list::-webkit-scrollbar-track { background: var(--bg-input); }\
    .nym-gateway-list::-webkit-scrollbar-thumb { background: var(--border-accent); border-radius: 2px; }\
    .nym-info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }\
    @media (max-width: 500px) { .nym-info-grid { grid-template-columns: 1fr; } }\
    .nym-info-item { background: var(--bg-secondary); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border-color); }\
    .nym-info-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 4px; }\
    .nym-info-value { font-size: 14px; color: var(--text-primary); word-break: break-all; }\
    .nym-info-value.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\
    .nym-account-logged-in { text-align: center; padding: 20px 0; }\
    .nym-account-id { background: var(--bg-input); padding: 12px 16px; border-radius: 8px; font-size: 12px; color: var(--text-secondary); word-break: break-all; margin-bottom: 16px; border: 1px solid var(--border-color); }\
    .nym-account-state { display: inline-block; padding: 6px 12px; background: var(--nym-green-dim); color: var(--nym-green); border-radius: 20px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px; }\
    .nym-account-actions { display: flex; justify-content: center; gap: 12px; }\
    .nym-footer { text-align: center; padding: 24px 0; border-top: 1px solid var(--border-color); margin-top: 24px; }\
    .nym-footer-info { display: flex; justify-content: center; gap: 32px; font-size: 12px; color: var(--text-muted); }\
    .nym-footer-item span { color: var(--text-secondary); }\
    .nym-tooltip { position: relative; display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; background: var(--border-color); border-radius: 50%; font-size: 10px; color: var(--text-muted); cursor: help; margin-left: 8px; }\
    .nym-tooltip::after { content: attr(data-tip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); padding: 8px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; font-size: 11px; color: var(--text-secondary); white-space: nowrap; opacity: 0; visibility: hidden; transition: all 0.2s; z-index: 100; margin-bottom: 8px; }\
    .nym-tooltip:hover::after { opacity: 1; visibility: visible; }\
    .nym-divider { height: 1px; background: var(--border-color); margin: 20px 0; }\
    .nym-text-center { text-align: center; }\
    .nym-text-muted { color: var(--text-muted); }\
    .nym-mt-16 { margin-top: 16px; }\
    .nym-mb-16 { margin-bottom: 16px; }\
    .cbi-map > h2, .cbi-map > .cbi-map-descr { display: none !important; }\
    .cbi-page-actions { display: none !important; }\
    .nym-container button.nym-btn, .nym-container button.nym-btn:hover, .nym-container button.nym-btn:focus, .nym-container button.nym-btn:active { background-image: none !important; box-shadow: none !important; outline: none !important; text-shadow: none !important; }\
    .nym-container button.nym-btn-danger, .nym-container button.nym-btn-danger:hover, .nym-container button.nym-btn-danger:focus, .nym-container button.nym-btn-danger:active { background: transparent !important; background-color: transparent !important; background-image: none !important; color: var(--danger) !important; border-color: var(--danger) !important; }\
    .nym-container button.nym-btn-danger:hover { background: var(--danger-dim) !important; background-color: var(--danger-dim) !important; }\
    .nym-hero-gateway-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-bottom: 24px; }\
    .nym-hero-gateway-panel { flex: 1 1 0; max-width: 280px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; transition: border-color 0.3s ease; text-align: left; }\
    .nym-hero-gateway-panel:hover { border-color: var(--border-accent); }\
    .nym-hero-gateway-panel .nym-gateway-box-title { margin-bottom: 14px; font-size: 11px; }\
    .nym-hero-gateway-panel .nym-select { font-size: 13px; padding: 0 16px; height: 44px; line-height: 44px; background-position: right 14px center; text-align: center; text-align-last: center; }\
    .nym-hero-gateway-panel .nym-gateway-list { max-height: 160px; margin-top: 14px; }\
    .nym-hero-gateway-panel .nym-gateway-option { padding: 10px 12px; font-size: 12px; }\
    .nym-hero-gateway-panel .nym-gateway-option-name { font-size: 12px; }\
    .nym-hero-gateway-panel .nym-gateway-loading { font-size: 12px; padding: 10px 0; text-align: center; }\
    .nym-hero-gateway-panel .nym-form-label { font-size: 10px; text-align: center; margin-top: 8px; margin-bottom: 10px; }\
    .nym-hero-center { flex: 0 0 auto; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 0 16px; }\
    .nym-hero-center .nym-status-ring { margin-bottom: 24px; }\
    .nym-hero-center .nym-uptime { margin-top: 8px; }\
    @media (max-width: 700px) { .nym-hero-gateway-row { flex-direction: column; align-items: center; } .nym-hero-gateway-panel { flex: 0 0 auto; max-width: 320px; width: 100%; } .nym-hero-center { order: -1; margin-bottom: 24px; } }\
    /* Service Management */\
    .nym-service-status-row { display: flex; gap: 24px; justify-content: center; margin-bottom: 16px; }\
    .nym-service-info { text-align: center; }\
    .nym-service-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px; }\
    .nym-service-value { font-size: 18px; color: var(--text-primary); font-variant-numeric: tabular-nums; }\
    .nym-daemon-status { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 500; text-transform: uppercase; letter-spacing: 1px; }\
    .nym-daemon-status.running { background: var(--nym-green-dim); color: var(--nym-green); }\
    .nym-daemon-status.stopped { background: var(--danger-dim); color: var(--danger); }\
'
});
