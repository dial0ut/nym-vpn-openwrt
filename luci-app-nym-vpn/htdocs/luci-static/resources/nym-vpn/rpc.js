'use strict';
'require baseclass';
'require rpc';

return baseclass.extend({
    init: rpc.declare({
        object: 'nym-vpn',
        method: 'init',
        params: []
    }),

    status: rpc.declare({
        object: 'nym-vpn',
        method: 'status',
        params: []
    }),

    // relax_independence is an optional one-shot boolean: that connect (and
    // its automatic reconnects) skips the gateway-independence criteria
    // without touching the persisted setting. Omitted (undefined) when the
    // caller passes nothing, so an older bridge sees the same request as
    // before.
    connect: rpc.declare({
        object: 'nym-vpn',
        method: 'connect',
        params: ['relax_independence']
    }),

    // Pre-connect check: which entry/exit pair the daemon would pick for the
    // saved selection and whether it satisfies the independence criteria.
    // {status: 'selected'|'needs_relaxed'|'none', entry?, exit?}.
    tentativeGateways: rpc.declare({
        object: 'nym-vpn',
        method: 'tentative_gateways',
        params: []
    }),

    disconnect: rpc.declare({
        object: 'nym-vpn',
        method: 'disconnect',
        params: []
    }),

    info: rpc.declare({
        object: 'nym-vpn',
        method: 'info',
        params: []
    }),

    gatewayGet: rpc.declare({
        object: 'nym-vpn',
        method: 'gateway_get',
        params: []
    }),

    gatewaySet: rpc.declare({
        object: 'nym-vpn',
        method: 'gateway_set',
        params: ['entry_country', 'exit_country', 'entry_id', 'exit_id', 'entry_random', 'exit_random', 'residential_exit']
    }),

    // Full typed list for one gateway type, served by the Rust rpcd bridge.
    // The view derives the country dropdown and per-country lists from one
    // response instead of a round-trip per country.
    gatewayListFull: rpc.declare({
        object: 'nym-vpn',
        method: 'gateway_list_full',
        params: ['gateway_type']
    }),

    gatewayListCountries: rpc.declare({
        object: 'nym-vpn',
        method: 'gateway_list_countries',
        params: ['gateway_type']
    }),

    gatewayListByCountry: rpc.declare({
        object: 'nym-vpn',
        method: 'gateway_list_by_country',
        params: ['gateway_type', 'country_code']
    }),

    tunnelGet: rpc.declare({
        object: 'nym-vpn',
        method: 'tunnel_get',
        params: []
    }),

    tunnelSet: rpc.declare({
        object: 'nym-vpn',
        method: 'tunnel_set',
        params: ['ipv6', 'two_hop', 'killswitch', 'circumvention', 'legacy_split_tunnel', 'stealth_api', 'always_on']
    }),

    // Gateway independence also rides on tunnel_set. Pass 'on'/'off' for the
    // one being changed and leave the other undefined so it is omitted from
    // the request and the daemon leaves it alone.
    gatewayIndependenceSet: rpc.declare({
        object: 'nym-vpn',
        method: 'tunnel_set',
        params: ['gateway_independence', 'family_reminders']
    }),

    // Mixnet tuning shares the tunnel_set ubus method (no new ACL surface);
    // separate declaration so callers don't have to pad the tunnel params.
    mixnetTuningSet: rpc.declare({
        object: 'nym-vpn',
        method: 'tunnel_set',
        params: ['loop_cover_delay', 'packet_delay', 'message_delay', 'disable_poisson', 'disable_cover']
    }),

    accountGet: rpc.declare({
        object: 'nym-vpn',
        method: 'account_get',
        params: []
    }),

    accountSet: rpc.declare({
        object: 'nym-vpn',
        method: 'account_set',
        params: ['mnemonic', 'mode']
    }),

    accountForget: rpc.declare({
        object: 'nym-vpn',
        method: 'account_forget',
        params: []
    }),

    accountReset: rpc.declare({
        object: 'nym-vpn',
        method: 'account_reset',
        params: []
    }),

    accountRotateKeys: rpc.declare({
        object: 'nym-vpn',
        method: 'account_rotate_keys',
        params: []
    }),

    networkGet: rpc.declare({
        object: 'nym-vpn',
        method: 'network_get',
        params: []
    }),

    lanGet: rpc.declare({
        object: 'nym-vpn',
        method: 'lan_get',
        params: []
    }),

    lanSet: rpc.declare({
        object: 'nym-vpn',
        method: 'lan_set',
        params: ['policy']
    }),

    inboundList: rpc.declare({
        object: 'nym-vpn',
        method: 'inbound_list',
        params: []
    }),

    inboundAdd: rpc.declare({
        object: 'nym-vpn',
        method: 'inbound_add',
        params: ['proto', 'dport', 'label']
    }),

    inboundDel: rpc.declare({
        object: 'nym-vpn',
        method: 'inbound_del',
        params: ['proto', 'dport']
    }),

    splitList: rpc.declare({
        object: 'nym-vpn',
        method: 'split_list',
        params: []
    }),

    splitAdd: rpc.declare({
        object: 'nym-vpn',
        method: 'split_add',
        params: ['type', 'mac', 'domain', 'label']
    }),

    splitDel: rpc.declare({
        object: 'nym-vpn',
        method: 'split_del',
        params: ['id']
    }),

    splitSetEnabled: rpc.declare({
        object: 'nym-vpn',
        method: 'split_set_enabled',
        params: ['id', 'enabled']
    }),

    splitStatus: rpc.declare({
        object: 'nym-vpn',
        method: 'split_status',
        params: []
    }),

    clientsList: rpc.declare({
        object: 'nym-vpn',
        method: 'clients_list',
        params: []
    }),

    dnsGet: rpc.declare({
        object: 'nym-vpn',
        method: 'dns_get',
        params: []
    }),

    dnsSet: rpc.declare({
        object: 'nym-vpn',
        method: 'dns_set',
        params: ['enabled', 'servers']
    }),

    adBlockGet: rpc.declare({
        object: 'nym-vpn',
        method: 'ad_block_get',
        params: []
    }),

    adBlockSet: rpc.declare({
        object: 'nym-vpn',
        method: 'ad_block_set',
        params: ['enabled']
    }),

    daemonStatus: rpc.declare({
        object: 'nym-vpn',
        method: 'daemon_status',
        params: []
    }),

    daemonRestart: rpc.declare({
        object: 'nym-vpn',
        method: 'daemon_restart',
        params: []
    }),

    daemonStart: rpc.declare({
        object: 'nym-vpn',
        method: 'daemon_start',
        params: []
    }),

    daemonStop: rpc.declare({
        object: 'nym-vpn',
        method: 'daemon_stop',
        params: []
    }),

    logsGet: rpc.declare({
        object: 'nym-vpn',
        method: 'logs_get',
        params: ['lines']
    }),

    diagnosticRun: rpc.declare({
        object: 'nym-vpn',
        method: 'diagnostic_run',
        params: ['skip_dns', 'skip_http', 'gateway']
    })
});
