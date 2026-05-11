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
        params: ['ipv6', 'two_hop', 'killswitch']
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
    })
});
