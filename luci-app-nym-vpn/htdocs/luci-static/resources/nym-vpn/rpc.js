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

    connect: rpc.declare({
        object: 'nym-vpn',
        method: 'connect',
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
        params: ['ipv6', 'two_hop', 'killswitch', 'circumvention', 'legacy_split_tunnel']
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

    watchdogGet: rpc.declare({
        object: 'nym-vpn',
        method: 'watchdog_get',
        params: []
    }),

    watchdogSet: rpc.declare({
        object: 'nym-vpn',
        method: 'watchdog_set',
        params: ['always_on', 'interval']
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
