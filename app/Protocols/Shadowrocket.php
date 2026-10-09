<?php

namespace App\Protocols;

use App\Utils\Helper;
use App\Support\AbstractProtocol;
use App\Models\Server;

class Shadowrocket extends AbstractProtocol
{
    public $flags = ['shadowrocket'];
    public $allowedProtocols = [
        Server::TYPE_SHADOWSOCKS,
        Server::TYPE_VMESS,
        Server::TYPE_VLESS,
        Server::TYPE_TROJAN,
        Server::TYPE_HYSTERIA,
        Server::TYPE_TUIC,
        Server::TYPE_ANYTLS,
        Server::TYPE_SOCKS,
    ];

    protected $protocolRequirements = [
        'shadowrocket.hysteria.protocol_settings.version' => [2 => '1993'],
        'shadowrocket.anytls.base_version' => '2592',
        'shadowrocket.trojan.protocol_settings.network' => [
            'whitelist' => ['tcp', 'ws', 'grpc', 'h2', 'httpupgrade'],
            'strict' => true,
        ],
    ];

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;

        $uri = '';
        //display remaining traffic and expire date
        $upload = round($user['u'] / (1024 * 1024 * 1024), 2);
        $download = round($user['d'] / (1024 * 1024 * 1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024 * 1024 * 1024), 2);
        $expiredDate = $user['expired_at'] === null ? 'N/A' : date('Y-m-d', $user['expired_at']);
        $uri .= "STATUS=🚀↑:{$upload}GB,↓:{$download}GB,TOT:{$totalTraffic}GB💡Expires:{$expiredDate}\r\n";
        foreach ($servers as $item) {
            if ($item['type'] === Server::TYPE_SHADOWSOCKS) {
                $uri .= self::buildShadowsocks($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_VMESS) {
                $uri .= self::buildVmess($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_VLESS) {
                $uri .= self::buildVless($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_TROJAN) {
                $uri .= self::buildTrojan($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_HYSTERIA) {
                $uri .= self::buildHysteria($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_TUIC) {
                $uri .= self::buildTuic($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_ANYTLS) {
                $uri .= self::buildAnyTLS($item['password'], $item);
            }
            if ($item['type'] === Server::TYPE_SOCKS) {
                $uri .= self::buildSocks($item['password'], $item);
            }
        }
        return response(base64_encode($uri))
            ->header('content-type', 'text/plain');
    }


    public static function buildShadowsocks($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $password = data_get($server, 'password', $password);
        $str = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode(data_get($protocol_settings, 'cipher') . ":{$password}")
        );
        $addr = Helper::wrapIPv6($server['host']);

        $uri = "ss://{$str}@{$addr}:{$server['port']}";
        $plugin = data_get($protocol_settings, 'plugin') == 'obfs' ? 'obfs-local' : data_get($protocol_settings, 'plugin');
        $plugin_opts = data_get($protocol_settings, 'plugin_opts');
        if ($plugin && $plugin_opts) {
            $uri .= '/?' . 'plugin=' . $plugin . ';' . rawurlencode($plugin_opts);
        }
        return $uri . "#{$name}\r\n";
    }

    public static function buildVmess($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $userinfo = base64_encode('auto:' . $uuid . '@' . Helper::wrapIPv6($server['host']) . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if (data_get($protocol_settings, 'tls')) {
            $config['tls'] = 1;
            if (data_get($protocol_settings, 'tls_settings')) {
                if (!!data_get($protocol_settings, 'tls_settings.allow_insecure'))
                    $config['allowInsecure'] = (int) data_get($protocol_settings, 'tls_settings.allow_insecure');
                if (!!data_get($protocol_settings, 'tls_settings.server_name'))
                    $config['peer'] = data_get($protocol_settings, 'tls_settings.server_name');
            }
        }

        switch (data_get($protocol_settings, 'network')) {
            case 'tcp':
                if (data_get($protocol_settings, 'network_settings.header.type', 'none') !== 'none') {
                    $config['obfs'] = data_get($protocol_settings, 'network_settings.header.type');
                    $config['path'] = \Illuminate\Support\Arr::random(data_get($protocol_settings, 'network_settings.header.request.path', ['/']));
                    $config['obfsParam'] = \Illuminate\Support\Arr::random(data_get($protocol_settings, 'network_settings.header.request.headers.Host', ['www.example.com']));
                }
                break;
            case 'ws':
                $config['obfs'] = "websocket";
                $config['path'] = data_get($protocol_settings, 'network_settings.path');
                if ($host = data_get($protocol_settings, 'network_settings.headers.Host')) {
                    $config['obfsParam'] = $host;
                }
                break;
            case 'grpc':
                $config['obfs'] = "grpc";
                $config['path'] = data_get($protocol_settings, 'network_settings.serviceName');
                $config['host'] = data_get($protocol_settings, 'tls_settings.server_name') ?? $server['host'];
                break;
            case 'httpupgrade':
                $config['obfs'] = "httpupgrade";
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['obfsParam'] = $host;
                }
            break;
            case 'h2':
                $config['obfs'] = "h2";
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host')) {
                    $config['obfsParam'] = $host[0] ?? $server['host'];
                    $config['peer'] = $host [0] ?? $server['host'];
                }
                break;
            case 'xhttp':
                $config['obfs'] = "xhttp";
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['obfsParam'] = $host;
                }
                if ($mode = data_get($protocol_settings, 'network_settings.mode', 'auto')) {
                    $config['mode'] = $mode;
                }
                break;
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVless($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];

        // xhttp 节点开启加密时：明文 userinfo + type=xhttp + encryption 下发 enc（Shadowrocket 明文格式靠 type 识别 xhttp 传输并读取 encryption），
        // 同时沿用私有 obfs/obfsParam 下发已有映射的传输参数。
        $enc = null;
        if (data_get($protocol_settings, 'network') === 'xhttp'
            && data_get($protocol_settings, 'encryption.enabled')
            && ($enc = data_get($protocol_settings, 'encryption.encryption'))) {
            $userinfo = $uuid . '@' . Helper::wrapIPv6($server['host']) . ':' . $server['port'];
        } else {
            $userinfo = base64_encode('auto:' . $uuid . '@' . Helper::wrapIPv6($server['host']) . ':' . $server['port']);
        }
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
        ];

        // 判断是否开启xtls
        if (data_get($protocol_settings, 'flow')) {
            $xtlsMap = [
                'none' => 0,
                'xtls-rprx-direct' => 1,
                'xtls-rprx-vision' => 2
            ];
            if (array_key_exists(data_get($protocol_settings, 'flow'), $xtlsMap)) {
                $config['tls'] = 1;
                $config['xtls'] = $xtlsMap[data_get($protocol_settings, 'flow')];
            }
        }
        switch (data_get($protocol_settings, 'tls')) {
            case 1:
                $config['tls'] = 1;
                $config['allowInsecure'] = (int) data_get($protocol_settings, 'tls_settings.allow_insecure');
                if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                    $config['peer'] = $serverName;
                }
                if ($fp = Helper::getTlsFingerprint(data_get($protocol_settings, 'utls'))) {
                    $config['fp'] = $fp;
                }
                break;
            case 2:
                $config['tls'] = 1;
                $config['sni'] = data_get($protocol_settings, 'reality_settings.server_name');
                $config['pbk'] = data_get($protocol_settings, 'reality_settings.public_key');
                $config['sid'] = data_get($protocol_settings, 'reality_settings.short_id');
                if ($fp = Helper::getTlsFingerprint(data_get($protocol_settings, 'utls'))) {
                    $config['fp'] = $fp;
                }
                break;
            default:
                break;
        }
        switch (data_get($protocol_settings, 'network')) {
            case 'tcp':
                if (data_get($protocol_settings, 'network_settings.header.type', 'none') !== 'none') {
                    $config['obfs'] = data_get($protocol_settings, 'network_settings.header.type');
                    $config['path'] = \Illuminate\Support\Arr::random(data_get($protocol_settings, 'network_settings.header.request.path', ['/']));
                    $config['obfsParam'] = \Illuminate\Support\Arr::random(data_get($protocol_settings, 'network_settings.header.request.headers.Host', ['www.example.com']));
                }
                break;
            case 'ws':
                $config['obfs'] = "websocket";
                if (data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = data_get($protocol_settings, 'network_settings.path');
                }

                if ($host = data_get($protocol_settings, 'network_settings.headers.Host')) {
                    $config['obfsParam'] = $host;
                }
                break;
            case 'grpc':
                $config['obfs'] = "grpc";
                $config['path'] = data_get($protocol_settings, 'network_settings.serviceName');
                $config['host'] = data_get($protocol_settings, 'tls_settings.server_name') ?? $server['host'];
                break;
            case 'kcp':
                $config['obfs'] = "kcp";
                if ($seed = data_get($protocol_settings, 'network_settings.seed')) {
                    $config['path'] = $seed;
                }
                $config['type'] = data_get($protocol_settings, 'network_settings.header.type', 'none');
                break;
            case 'h2':
                $config['obfs'] = "h2";
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['obfsParam'] = $host;
                }
                break;
            case 'httpupgrade':
                $config['obfs'] = "httpupgrade";
                if ($path = data_get($protocol_settings, 'network_settings.path')) {
                    $config['path'] = $path;
                }
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host'])) {
                    $config['obfsParam'] = $host;
                }
                break;
            case 'xhttp':
                $config['obfs'] = "xhttp";
                // Allow HTTP/2 when the upload TLS/Reality connection negotiates h2.
                // Keep normal ALPN negotiation and independent download settings unchanged.
                if (in_array((int)data_get($protocol_settings, 'tls'), [1, 2], true)) {
                    $config['h2'] = 1;
                }
                // 明文格式下 Shadowrocket 依赖 type 识别 xhttp 传输，encryption 才会被读取为 enc
                if ($enc !== null) {
                    $config['type'] = 'xhttp';
                    $config['encryption'] = $enc;
                }
                $settings = data_get($protocol_settings, 'network_settings') ?? [];
                if ($path = data_get($settings, 'path')) {
                    $config['path'] = $path;
                }
                if ($mode = data_get($settings, 'mode', 'auto')) {
                    $config['mode'] = $mode;
                }
                $config['obfsParam'] = json_encode(
                    self::buildXhttpParameters($settings, $protocol_settings, $server),
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
                );
                break;
        }

        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vless" . "://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

    private static function xhttpExtra(array $settings): array
    {
        if (!array_key_exists('extra', $settings)) {
            return $settings;
        }
        if ($settings['extra'] === null) {
            return [];
        }
        if (!is_array($settings['extra'])) {
            throw new \InvalidArgumentException('XHTTP extra must be an object.');
        }
        // Xray extra replaces advanced root fields; host/path/mode stay at the root.
        return $settings['extra'];
    }

    private static function xhttpHost(...$candidates): string
    {
        foreach ($candidates as $candidate) {
            if (is_string($candidate) && $candidate !== '') {
                return $candidate;
            }
        }
        return '';
    }

    private static function xhttpSessionTable(string $table): string
    {
        // Xray predefined names are case-sensitive; Shadowrocket receives the alphabet.
        $predefined = [
            'ALPHABET' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'Alphabet' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'BASE36' => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'Base62' => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'HEX' => '0123456789ABCDEF',
            'alphabet' => 'abcdefghijklmnopqrstuvwxyz',
            'base36' => '0123456789abcdefghijklmnopqrstuvwxyz',
            'hex' => '0123456789abcdef',
            'number' => '0123456789',
        ];
        return $predefined[$table] ?? $table;
    }

    private static function xhttpChromeHeaders(array $headers): array
    {
        $uaKey = null;
        foreach ($headers as $name => $value) {
            if (strcasecmp($name, 'User-Agent') !== 0) {
                continue;
            }
            if ($uaKey !== null) {
                // Ambiguous duplicate names retain their original values.
                return $headers;
            }
            $uaKey = $name;
        }
        if ($uaKey === null || $headers[$uaKey] !== 'chrome') {
            return $headers;
        }

        // Fixed Chrome150 fetch profile captured from Xray b26a91d and tested on
        // Shadowrocket 2.2.92. Keep the UA and Client Hints version paired.
        $defaults = [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
            'Accept' => '*/*',
            'Accept-Language' => 'en-US,en;q=0.9',
            'Cache-Control' => 'no-cache',
            'DNT' => '1',
            'Pragma' => 'no-cache',
            'Priority' => 'u=1, i',
            'Sec-CH-UA' => '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
            'Sec-CH-UA-Mobile' => '?0',
            'Sec-CH-UA-Platform' => '"Windows"',
            'Sec-Fetch-Dest' => 'empty',
            'Sec-Fetch-Mode' => 'cors',
            'Sec-Fetch-Site' => 'same-origin',
        ];
        $headers[$uaKey] = $defaults['User-Agent'];
        $present = array_fill_keys(array_map('strtolower', array_keys($headers)), true);
        foreach ($defaults as $name => $value) {
            // Explicit values, including empty strings, override defaults.
            if (!isset($present[strtolower($name)])) {
                $headers[$name] = $value;
            }
        }
        return $headers;
    }

    private static function buildXhttpParameters(array $settings, array $protocolSettings, array $server): array
    {
        $extra = self::xhttpExtra($settings);
        $mode = data_get($settings, 'mode') ?: 'auto';
        $packet = in_array($mode, ['auto', 'packet-up'], true);
        $stream = in_array($mode, ['auto', 'stream-up', 'stream-one'], true);
        $session = in_array($mode, ['auto', 'packet-up', 'stream-up'], true);
        $tlsMode = (int)data_get($protocolSettings, 'tls');
        $sni = $tlsMode === 2 ? data_get($protocolSettings, 'reality_settings.server_name')
            : ($tlsMode === 1 ? data_get($protocolSettings, 'tls_settings.server_name') : null);
        $params = ['Host' => self::xhttpHost(data_get($settings, 'host'), $sni, $server['host'])];

        // Root obfsParam entries are HTTP headers; the empty key is reserved for native options.
        $headers = data_get($extra, 'headers') ?? [];
        if (!is_array($headers)) {
            throw new \InvalidArgumentException('XHTTP headers must be an object.');
        }
        foreach ($headers as $name => $value) {
            if (!is_string($name) || !preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name)
                || strcasecmp($name, 'Host') === 0 || !is_string($value)
                || strpbrk($value, "\r\n") !== false) {
                throw new \InvalidArgumentException('XHTTP headers must use valid names and string values; set Host with xhttpSettings.host.');
            }
        }
        foreach (self::xhttpChromeHeaders($headers) as $name => $value) {
            $params[$name] = $value;
        }

        $inner = [];
        foreach (['xPaddingBytes', 'xPaddingKey', 'xPaddingHeader', 'xPaddingPlacement', 'xPaddingMethod', 'uplinkHTTPMethod'] as $key) {
            if (isset($extra[$key])) {
                $inner[$key] = $extra[$key];
            }
        }
        if (isset($extra['xPaddingObfsMode'])) {
            $inner['xPaddingObfsMode'] = (bool)$extra['xPaddingObfsMode'];
        }
        // Shadowrocket 2.2.92 uses raw token length; Xray checks HPACK Huffman bytes.
        // Packet-up and stream-up tokenish/header behavior was verified with Shadowrocket 2.2.92.
        // 160 Base62 characters encode to at least 100 bytes; retain the 1000 upper limit.
        if (in_array($mode, ['packet-up', 'stream-up'], true)
            && ($inner['xPaddingMethod'] ?? null) === 'tokenish'
            && ($extra['xPaddingObfsMode'] ?? null) === true
            && ($inner['xPaddingPlacement'] ?? null) === 'header'
            && ($inner['xPaddingBytes'] ?? null) === '100-1000') {
            $inner['xPaddingBytes'] = '160-1000';
        }
        if ($stream && isset($extra['noGRPCHeader'])) {
            $inner['noGRPCHeader'] = (bool)$extra['noGRPCHeader'];
        }
        if ($session) {
            foreach (['sessionPlacement' => 'sessionIDPlacement', 'sessionKey' => 'sessionIDKey'] as $output => $canonical) {
                if (isset($extra[$canonical]) || isset($extra[$output])) {
                    $inner[$output] = $extra[$canonical] ?? $extra[$output];
                }
            }
            foreach (['sessionTable' => 'sessionIDTable', 'sessionLength' => 'sessionIDLength'] as $output => $canonical) {
                $source = array_key_exists($canonical, $extra) ? $canonical : $output;
                if (isset($extra[$source])) {
                    $value = (string)$extra[$source];
                    $inner[$output] = $output === 'sessionTable' && $source === $canonical
                        ? self::xhttpSessionTable($value) : $value;
                }
            }
        }
        if ($packet) {
            foreach (['seqPlacement', 'seqKey', 'uplinkDataPlacement', 'uplinkDataKey'] as $key) {
                if (isset($extra[$key])) {
                    $inner[$key] = $extra[$key];
                }
            }
            foreach (['uplinkChunkSize', 'scMaxEachPostBytes', 'scMinPostsIntervalMs'] as $key) {
                if (isset($extra[$key])) {
                    $inner[$key] = (string)$extra[$key];
                }
            }
        }
        $xmux = data_get($extra, 'xmux') ?? [];
        foreach (['maxConcurrency', 'maxConnections', 'cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs', 'hKeepAlivePeriod'] as $key) {
            if (isset($xmux[$key])) {
                $value = $xmux[$key];
                // Preserve the existing Shadowrocket representation, including explicit zero ranges.
                $inner[$key] = in_array($key, ['maxConnections', 'cMaxReuseTimes'], true) && !is_string($value)
                    ? "{$value}-{$value}" : (string)$value;
            }
        }
        if ($session && ($download = data_get($extra, 'downloadSettings'))) {
            $address = data_get($download, 'address', '');
            $security = data_get($download, 'security');
            $downloadSni = $security === 'reality' ? data_get($download, 'realitySettings.serverName')
                : ($security === 'tls' ? data_get($download, 'tlsSettings.serverName') : null);
            $inner['downloadTargetHost'] = $address;
            $inner['downloadTargetPort'] = (string)data_get($download, 'port', 443);
            $inner['downloadServerName'] = in_array($security, ['tls', 'reality'], true)
                ? self::xhttpHost($downloadSni, $address) : '';
            $inner['downloadHTTPHost'] = self::xhttpHost(
                data_get($download, 'xhttpSettings.host'), $downloadSni, $address
            );
        }
        // Advanced download fields still need a verified native schema.
        if ($inner !== []) {
            $params[''] = $inner;
        }
        return $params;
    }

    public static function buildTrojan($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $params = [];
        $tlsMode = (int) data_get($protocol_settings, 'tls', 1);

        switch ($tlsMode) {
            case 2: // Reality
                $params['security'] = 'reality';
                $params['pbk'] = data_get($protocol_settings, 'reality_settings.public_key');
                $params['sid'] = data_get($protocol_settings, 'reality_settings.short_id');
                $params['sni'] = data_get($protocol_settings, 'reality_settings.server_name');
                break;
            default: // Standard TLS
                $params['allowInsecure'] = (int) data_get($protocol_settings, 'tls_settings.allow_insecure');
                if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                    $params['peer'] = $serverName;
                }
                break;
        }

        switch (data_get($protocol_settings, 'network')) {
            case 'grpc':
                $params['obfs'] = 'grpc';
                $params['path'] = data_get($protocol_settings, 'network_settings.serviceName');
                break;
            case 'ws':
                $host = data_get($protocol_settings, 'network_settings.headers.Host');
                $path = data_get($protocol_settings, 'network_settings.path');
                $params['plugin'] = "obfs-local;obfs=websocket;obfs-host={$host};obfs-uri={$path}";
                break;
            case 'h2':
                $params['obfs'] = 'h2';
                if ($path = data_get($protocol_settings, 'network_settings.path'))
                    $params['path'] = $path;
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host']))
                    $params['obfsParam'] = is_array($host) ? $host[0] : $host;
                break;
            case 'httpupgrade':
                $params['obfs'] = 'httpupgrade';
                if ($path = data_get($protocol_settings, 'network_settings.path'))
                    $params['path'] = $path;
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host']))
                    $params['obfsParam'] = $host;
                break;
            case 'xhttp':
                $params['obfs'] = 'xhttp';
                if ($path = data_get($protocol_settings, 'network_settings.path'))
                    $params['path'] = $path;
                if ($host = data_get($protocol_settings, 'network_settings.host', $server['host']))
                    $params['obfsParam'] = $host;
                if ($mode = data_get($protocol_settings, 'network_settings.mode', 'auto'))
                    $params['mode'] = $mode;
                break;
        }
        $query = http_build_query($params);
        $addr = Helper::wrapIPv6($server['host']);

        $uri = "trojan://{$password}@{$addr}:{$server['port']}?{$query}&tfo=1#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildHysteria($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $uri = ''; // 初始化变量

        switch (data_get($protocol_settings, 'version')) {
            case 1:
                $params = [
                    "auth" => $password,
                    "upmbps" => data_get($protocol_settings, 'bandwidth.up'),
                    "downmbps" => data_get($protocol_settings, 'bandwidth.down'),
                    "protocol" => 'udp',
                    "fastopen" => 1,
                ];
                if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
                    $params['peer'] = $serverName;
                }
                if (data_get($protocol_settings, 'obfs.open')) {
                    $params["obfs"] = "xplus";
                    $params["obfsParam"] = data_get($protocol_settings, 'obfs.password');
                }
                $params['insecure'] = data_get($protocol_settings, 'tls.allow_insecure');
                if (isset($server['ports']))
                    $params['mport'] = $server['ports'];
                $query = http_build_query($params);
                $addr = Helper::wrapIPv6($server['host']);

                $uri = "hysteria://{$addr}:{$server['port']}?{$query}#{$server['name']}";
                $uri .= "\r\n";
                break;
            case 2:
                $params = [
                    "obfs" => 'none',
                    "fastopen" => 1
                ];
                if (($upMbps = data_get($protocol_settings, 'bandwidth.up')) > 0) {
                    $params['upmbps'] = $upMbps;
                }
                if (($downMbps = data_get($protocol_settings, 'bandwidth.down')) > 0) {
                    $params['downmbps'] = $downMbps;
                }
                if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
                    $params['peer'] = $serverName;
                }
                if (data_get($protocol_settings, 'obfs.open')) {
                    $params['obfs'] = data_get($protocol_settings, 'obfs.type');
                    $params['obfs-password'] = data_get($protocol_settings, 'obfs.password');
                }
                $params['insecure'] = data_get($protocol_settings, 'tls.allow_insecure');
                if (isset($protocol_settings['hop_interval'])) {
                    $params['keepalive'] = data_get($protocol_settings, 'hop_interval');
                }
                if (isset($server['ports'])) {
                    $params['mport'] = $server['ports'];
                }
                $query = http_build_query($params);
                $addr = Helper::wrapIPv6($server['host']);

                $uri = "hysteria2://{$password}@{$addr}:{$server['port']}?{$query}#{$server['name']}";
                $uri .= "\r\n";
                break;
        }
        return $uri;
    }
    public static function buildTuic($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $params = [
            'alpn' => data_get($protocol_settings, 'alpn'),
            'sni' => data_get($protocol_settings, 'tls.server_name'),
            'insecure' => data_get($protocol_settings, 'tls.allow_insecure'),
            'congestion_control' => data_get($protocol_settings, 'congestion_control', 'cubic')
        ];
        if (data_get($protocol_settings, 'version') === 4) {
            $params['token'] = $password;
        } else {
            $params['uuid'] = $password;
            $params['password'] = $password;
        }
        $query = http_build_query($params);
        $addr = Helper::wrapIPv6($server['host']);
        $uri = "tuic://{$addr}:{$server['port']}?{$query}#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildAnyTLS($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $params = [
            'sni' => data_get($protocol_settings, 'tls.server_name'),
            'insecure' => data_get($protocol_settings, 'tls.allow_insecure')
        ];
        $query = http_build_query($params);
        $addr = Helper::wrapIPv6($server['host']);
        $uri = "anytls://{$password}@{$addr}:{$server['port']}?{$query}#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildSocks($password, $server)
    {   
        $protocol_settings = $server['protocol_settings'];
        $name = rawurlencode($server['name']);
        $addr = Helper::wrapIPv6($server['host']);
        $uri = 'socks://' . base64_encode("{$password}:{$password}@{$addr}:{$server['port']}") . "?method=auto#{$name}";
        $uri .= "\r\n";
        return $uri;
    }
}
