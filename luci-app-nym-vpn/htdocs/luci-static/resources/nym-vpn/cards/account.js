'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.ui as nymUI';
'require nym-vpn.components.card as card';
'require nym-vpn.components.modal as modal';
'require nym-vpn.components.toast as toast';
'require nym-vpn.flows.daemon as daemonFlow';

// Account card. The body is rebuilt from a fresh `account get` each time
// refresh() runs, so a recovered account clears the error panel without a
// manual page reload (the 1.27.1 "error stays until refresh" report).

var E = dom.create.bind(dom);

return baseclass.extend({
    render: function(store, api) {
        var bodyEl;

        var refresh = function() {
            return api.accountGet().then(function(acct) {
                if (bodyEl) {
                    dom.content(bodyEl, buildBody(api.computeAccountFlags(acct)));
                }
            }).catch(function() { /* leave the existing card on transient errors */ });
        };

        var login = function(ev) {
            ev.preventDefault();
            var fd = new FormData(ev.target);
            // Collapse whitespace: the field is a textarea, so a pasted
            // phrase can carry newlines and double spaces, and the
            // daemon-side validator only accepts lowercase letters and
            // single spaces.
            var mnemonic = (fd.get('mnemonic') || '').replace(/\s+/g, ' ').trim();
            var mode = fd.get('mode') || 'api';

            if (!mnemonic) {
                toast.show('Recovery phrase is required', 'error');
                return;
            }

            modal.show('Logging In', 'Configuring account...');

            api.accountSet(mnemonic, mode).then(function(result) {
                if (result && result.success) {
                    // Poll for ReadyToConnect status
                    var pollCount = 0;
                    var maxPolls = 30; // 30 seconds max

                    var pollAccountStatus = function() {
                        pollCount++;
                        api.accountGet().then(function(accountResult) {
                            var accState = (accountResult && accountResult.state) || '';
                            var accIdentity = (accountResult && accountResult.identity) || '';

                            if (accState === 'ReadyToConnect' || accState.indexOf('Ready') >= 0) {
                                modal.setSuccess('Ready', 'Account configured', '✓');
                                setTimeout(function() {
                                    modal.fadeOut(function() {
                                        location.reload();
                                    });
                                }, 800);
                            } else if (accState.indexOf('Error') >= 0 || accIdentity.indexOf('Error') >= 0) {
                                modal.hide();
                                toast.show('Account error: ' + (accState || accIdentity), 'error');
                            } else if (pollCount < maxPolls) {
                                modal.update(accState || 'Please wait...');
                                setTimeout(pollAccountStatus, 1000);
                            } else {
                                modal.hide();
                                toast.show('Account setup timed out. Please refresh.', 'warning');
                            }
                        }).catch(function() {
                            if (pollCount < maxPolls) {
                                setTimeout(pollAccountStatus, 1000);
                            } else {
                                modal.hide();
                                toast.show('Account setup timed out', 'warning');
                            }
                        });
                    };

                    setTimeout(pollAccountStatus, 1000);
                } else {
                    modal.hide();
                    toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                modal.hide();
                toast.show('Error: ' + err.message, 'error');
            });
        };

        var logout = function() {
            modal.confirm(
                'Logout',
                'This will disconnect and remove your account. You will need your recovery phrase to log back in.',
                '⚠',
                function() {
                    modal.show('Logging Out', 'Please wait...');

                    var doLogout = function() {
                        modal.update('Removing account...');
                        api.accountForget().then(function(result) {
                            if (result && result.success) {
                                modal.setSuccess('Done', 'Account removed', '✓');
                                setTimeout(function() {
                                    modal.fadeOut(function() {
                                        location.reload();
                                    });
                                }, 800);
                            } else {
                                modal.hide();
                                toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                            }
                        }).catch(function(err) {
                            modal.hide();
                            toast.show('Error: ' + err.message, 'error');
                        });
                    };

                    // Check if connected, disconnect first
                    api.status().then(function(st) {
                        if (st && (st.state === 'connected' || st.state === 'connecting')) {
                            modal.update('Disconnecting...');
                            api.disconnect().then(function() {
                                var pollCount = 0;
                                var pollDisconnect = function() {
                                    pollCount++;
                                    api.status().then(function(s) {
                                        if (s && s.state === 'disconnected') {
                                            doLogout();
                                        } else if (pollCount < 30) {
                                            setTimeout(pollDisconnect, 500);
                                        } else {
                                            doLogout(); // Try anyway after timeout
                                        }
                                    }).catch(function() {
                                        doLogout();
                                    });
                                };
                                setTimeout(pollDisconnect, 500);
                            }).catch(function() {
                                doLogout(); // Try logout anyway
                            });
                        } else {
                            doLogout();
                        }
                    }).catch(function() {
                        doLogout();
                    });
                }
            );
        };

        // Hard account-state reset for the desync where `forget` can't clear
        // a stranded account. Stops the daemon, wipes the account/key store,
        // and restarts with a delay (the proven manual recovery). Last resort.
        var reset = function() {
            modal.confirm(
                'Reset account state',
                'Use this only if logging out fails or the account is stuck. It stops the VPN service, erases the stored account and keys on this device, then restarts. Your saved settings are kept, but you will need your recovery phrase to log back in.',
                '⚠',
                function() {
                    modal.show('Resetting', 'Stopping service and clearing account state…');
                    api.accountReset().then(function(result) {
                        if (result && result.success) {
                            modal.setSuccess('Done', 'Account state reset', '✓');
                            setTimeout(function() {
                                modal.fadeOut(function() {
                                    location.reload();
                                });
                            }, 900);
                        } else {
                            modal.hide();
                            toast.show('Reset failed: ' + ((result && result.error) || 'Unknown'), 'error');
                        }
                    }).catch(function(err) {
                        modal.hide();
                        toast.show('Error: ' + err.message, 'error');
                    });
                }
            );
        };

        var rotateKeys = function() {
            api.status().then(function(st) {
                if (st && (st.state === 'connected' || st.state === 'connecting')) {
                    toast.show('Please disconnect before rotating keys', 'warning');
                    return;
                }

                modal.show('Rotating Keys', 'Generating new keys...', '🔑');
                api.accountRotateKeys().then(function(result) {
                    modal.hide();
                    if (result && result.success) {
                        toast.show('Keys rotated successfully', 'success');
                    } else {
                        toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                    }
                }).catch(function(err) {
                    modal.hide();
                    toast.show('Error: ' + err.message, 'error');
                });
            });
        };

        var copyIdentity = function(text, btn) {
            if (!text) return;
            var flash = function() {
                if (!btn) return;
                btn.classList.add('copied');
                setTimeout(function() { btn.classList.remove('copied'); }, 1400);
            };
            nymUI.copyText(text, function(ok) {
                if (ok) {
                    flash();
                    toast.show('Device identity copied', 'success');
                } else {
                    toast.show('Copy failed', 'error');
                }
            });
        };

        var buildBody = function(flags) {
            var identity = flags.identity;
            var state = flags.state;
            var accountStatusLabel = (state || '').trim() || 'Active';

            // Checked before anything else: with no answer from the daemon we
            // know nothing about the account, so say that instead of guessing.
            if (flags.isUnavailable) {
                var unavailableBody = [
                    E('div', { 'class': 'nym-account-state', 'style': 'background: var(--danger-dim); color: var(--danger)' },
                        flags.daemonRunning ? 'Service not responding' : 'Service not running'),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin: 16px 0' },
                        'The account state is unknown because the VPN service could not be reached. Your recovery phrase is still stored on this device — nothing has been removed.')
                ];
                if (!flags.daemonEnabled) {
                    unavailableBody.push(E('div', { 'class': 'nym-card-description', 'style': 'margin-bottom: 16px; opacity: 0.8' },
                        'nym-vpnd is also not enabled at boot, so it will stay down after a reboot. Enable it from the Service Management card or with: /etc/init.d/nym-vpnd enable'));
                }
                unavailableBody.push(E('button', {
                    'class': 'nym-btn nym-btn-primary',
                    'type': 'button',
                    'style': 'width: 100%',
                    'click': function() { daemonFlow.run(flags.daemonRunning ? 'restart' : 'start', store, api); }
                }, flags.daemonRunning ? 'Restart service' : 'Start service'));
                return E('div', { 'class': 'nym-account-logged-in' }, unavailableBody);
            }

            if (flags.isLoggedIn) {
                var copyBtn = E('button', {
                    'class': 'nym-identity-copy',
                    'type': 'button',
                    'title': 'Copy device identity'
                });
                copyBtn.innerHTML = assets.iconCopy;
                copyBtn.addEventListener('click', function(ev) {
                    ev.preventDefault();
                    copyIdentity(identity, copyBtn);
                });

                var rotateBtn = E('button', {
                    'class': 'nym-card-action rotate',
                    'type': 'button',
                    'click': rotateKeys
                });
                rotateBtn.innerHTML = assets.iconRefresh + '<span>Rotate keys</span>';

                var signOutBtn = E('button', {
                    'class': 'nym-card-action danger',
                    'type': 'button',
                    'click': logout
                });
                signOutBtn.innerHTML = assets.iconPower + '<span>Sign out</span>';

                return E('div', { 'class': 'nym-account-panel' }, [
                    E('div', { 'class': 'nym-info-frame' }, [
                        E('div', { 'class': 'nym-info-frame-label' }, 'Device Identity'),
                        E('div', { 'class': 'nym-info-frame-main' }, [
                            E('div', { 'class': 'nym-info-frame-id-row' }, [
                                E('div', { 'class': 'nym-info-frame-value' }, identity),
                                copyBtn
                            ]),
                            E('div', { 'class': 'nym-card-status' }, [
                                E('span', { 'class': 'nym-card-status-indicator' }),
                                E('span', { 'class': 'nym-card-status-text' }, accountStatusLabel)
                            ])
                        ])
                    ]),
                    E('div', { 'class': 'nym-card-actions-bar' }, [
                        rotateBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        signOutBtn
                    ])
                ]);
            }

            if (flags.hasError) {
                return E('div', { 'class': 'nym-account-logged-in' }, [
                    E('div', { 'class': 'nym-account-state', 'style': 'background: var(--danger-dim); color: var(--danger)' }, state || identity),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin: 16px 0' }, 'There is an issue with the account. You may need to logout and try again.'),
                    E('button', { 'class': 'nym-btn nym-btn-danger', 'style': 'width: 100%', 'click': logout }, 'Logout'),
                    E('button', { 'class': 'nym-btn nym-btn-secondary', 'style': 'width: 100%; margin-top: 8px', 'click': reset }, 'Reset account state'),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin-top: 8px; opacity: 0.7' }, 'If Logout fails or the state is stuck, Reset stops the service and clears the stored account.')
                ]);
            }

            var form = E('form', { 'submit': login }, [
                E('div', { 'class': 'nym-card-description' },
                    'Enter your Nym account recovery phrase to connect.'),
                E('div', { 'class': 'nym-form-group' }, [
                    E('label', { 'class': 'nym-form-label' }, 'Recovery Phrase'),
                    // A textarea, not a text input: browsers ignore
                    // autocomplete="off" on inputs and helpfully autofill the
                    // saved LuCI login here (users see the word "root" appear
                    // in the field). Password managers do not autofill
                    // textareas, and a 24-word phrase wraps instead of
                    // scrolling. FormData.get('mnemonic') is unchanged.
                    E('textarea', {
                        'class': 'nym-input',
                        'name': 'mnemonic',
                        'rows': '3',
                        'autocomplete': 'off',
                        'autocapitalize': 'off',
                        'autocorrect': 'off',
                        'spellcheck': 'false',
                        'style': 'resize: vertical',
                        'placeholder': 'Enter your recovery phrase...'
                    })
                ]),
                E('button', { 'class': 'nym-btn nym-btn-primary', 'type': 'submit', 'style': 'width: 100%' }, 'Login')
            ]);

            // Desync recovery: the daemon reports LoggedOut yet still has a
            // leftover device identity (the "says not set but won't forget"
            // case). Offer the hard reset so the user isn't stuck.
            if (flags.isLoggedOut && flags.identity) {
                return E('div', {}, [
                    form,
                    E('div', { 'class': 'nym-card-description', 'style': 'margin-top: 16px; opacity: 0.7' }, 'Stale account data detected on this device. If login fails, reset the stored account state.'),
                    E('button', { 'class': 'nym-btn nym-btn-secondary', 'style': 'width: 100%; margin-top: 8px', 'click': reset }, 'Reset account state')
                ]);
            }

            return form;
        };

        var c = card.create({
            icon: assets.iconUser,
            title: 'Account',
            id: 'nym-card-account',
            body: [buildBody(api.computeAccountFlags(store.data.account))]
        });
        bodyEl = c.body;

        // Re-render when the account error situation or the daemon's
        // availability changes, so a recovered account (or a newly-failed
        // one) reflects live instead of waiting for a page reload.
        store.on('status', function(ev) {
            if (ev.errorReasonChanged) refresh();
            if (ev.availabilityChanged) refresh();
        });
        store.on('account-recheck', refresh);

        return c.el;
    }
});
