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
                $config['obfs'] = 'xhttp';
                // Preserve the current template's upload HTTP/2 option for TLS/Reality.
                if (in_array((int)data_get($protocol_settings, 'tls'), [1, 2], true)) {
                    $config['h2'] = 1;
                }
                if ($enc !== null) {
                    $config['type'] = 'xhttp';
                    $config['encryption'] = $enc;
                }
                $settings = self::xhttpObject(data_get($protocol_settings, 'network_settings') ?? [], 'XHTTP network_settings');
                if (array_key_exists('path', $settings)) {
                    $config['path'] = $settings['path'];
                }
                $config['mode'] = array_key_exists('mode', $settings) ? $settings['mode'] : 'auto';
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

    private static function xhttpObject($value, string $label): array
    {
        if (is_string($value)) {
            $value = json_decode($value, false, 512, JSON_THROW_ON_ERROR);
        }
        if ($value instanceof \stdClass) {
            return get_object_vars($value);
        }
        if (is_array($value) && ($value === [] || !array_is_list($value))) {
            return $value;
        }
        throw new \InvalidArgumentException($label . ' must be a JSON object.');
    }

    private static function xhttpExtra(array $settings): array
    {
        if (array_key_exists('extra', $settings)) {
            // Xray extra replaces advanced root options; host/path/mode stay at the root.
            return $settings['extra'] === null ? [] : self::xhttpObject($settings['extra'], 'XHTTP extra');
        }
        unset($settings['host'], $settings['path'], $settings['mode']);
        return $settings;
    }

    private static function xhttpHost(...$candidates): string
    {
        foreach ($candidates as $candidate) {
            if (is_string($candidate) && $candidate !== '') {
                if (strpbrk($candidate, "\r\n") !== false) {
                    throw new \InvalidArgumentException('XHTTP Host must not contain CR/LF.');
                }
                return $candidate;
            }
        }
        return '';
    }

    private static function xhttpSessionTable(string $table): string
    {
        // Native sessionTable uses an alphabet; retain sessionIDTable separately below.
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

    private static function xhttpNativeString($value, string $key): string
    {
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            throw new \InvalidArgumentException('XHTTP ' . $key . ' must be a number or range string.');
        }
        return (string)$value;
    }

    private static function buildXhttpParameters(array $settings, array $protocolSettings, array $server): array
    {
        $extra = self::xhttpExtra($settings);
        $headers = ($extra['headers'] ?? null) === null ? []
            : self::xhttpObject($extra['headers'], 'XHTTP headers');
        $headerHost = null;
        $hasHeaderHost = false;
        foreach ($headers as $name => $value) {
            $name = (string)$name;
            if (!preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name)
                || !is_string($value) || strpbrk($value, "\r\n") !== false) {
                throw new \InvalidArgumentException('XHTTP headers must use valid names and string values without CR/LF.');
            }
            if (strcasecmp($name, 'Host') === 0) {
                if ($hasHeaderHost) {
                    throw new \InvalidArgumentException('XHTTP headers contain duplicate Host names.');
                }
                $hasHeaderHost = true;
                $headerHost = $value;
            }
        }
        $tlsMode = (int)data_get($protocolSettings, 'tls');
        $sni = $tlsMode === 2 ? data_get($protocolSettings, 'reality_settings.server_name')
            : ($tlsMode === 1 ? data_get($protocolSettings, 'tls_settings.server_name') : null);
        $params = ['Host' => self::xhttpHost(data_get($settings, 'host'), $headerHost, $sni, $server['host'])];
        foreach ($headers as $name => $value) {
            if (strcasecmp((string)$name, 'Host') !== 0) {
                // Keep user-supplied values, including "chrome" and empty strings, unchanged.
                $params[$name] = $value;
            }
        }

        // Keep every advanced option, including future keys and complete nested downloadSettings.
        // Preservation is not a claim that the client's runtime understands each option.
        $inner = $extra;
        unset($inner['headers']);

        // Add verified native aliases without discarding the original canonical fields.
        foreach (['sessionPlacement' => 'sessionIDPlacement', 'sessionKey' => 'sessionIDKey',
            'sessionTable' => 'sessionIDTable', 'sessionLength' => 'sessionIDLength'] as $output => $canonical) {
            if (array_key_exists($canonical, $extra) && $extra[$canonical] !== null) {
                $value = $extra[$canonical];
                if ($output === 'sessionTable') {
                    $value = self::xhttpSessionTable(self::xhttpNativeString($value, $canonical));
                }
                $inner[$output] = $value;
            }
        }
        foreach (['sessionTable', 'sessionLength', 'uplinkChunkSize', 'scMaxEachPostBytes', 'scMinPostsIntervalMs',
            'maxConcurrency', 'maxConnections', 'cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs', 'hKeepAlivePeriod'] as $key) {
            if (array_key_exists($key, $inner) && $inner[$key] !== null) {
                $inner[$key] = self::xhttpNativeString($inner[$key], $key);
            }
        }

        if (array_key_exists('xmux', $extra) && $extra['xmux'] !== null) {
            $xmux = self::xhttpObject($extra['xmux'], 'XHTTP xmux');
            // Retain the full object, including unknown future XMUX options and numeric zero.
            $inner['xmux'] = (object)$xmux;
            foreach (['maxConcurrency', 'maxConnections', 'cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs', 'hKeepAlivePeriod'] as $key) {
                if (array_key_exists($key, $xmux) && $xmux[$key] !== null) {
                    $value = $xmux[$key];
                    $native = self::xhttpNativeString($value, 'xmux.' . $key);
                    $inner[$key] = in_array($key, ['maxConnections', 'cMaxReuseTimes'], true) && !is_string($value)
                        ? $native . '-' . $native : $native;
                }
            }
        }

        if (array_key_exists('downloadSettings', $extra) && $extra['downloadSettings'] !== null) {
            $download = self::xhttpObject($extra['downloadSettings'], 'XHTTP downloadSettings');
            // No invented download headers/XMUX/ALPN keys: preserve their original structure.
            $inner['downloadSettings'] = (object)$download;
            $address = data_get($download, 'address');
            if (is_string($address) && $address !== '') {
                $security = data_get($download, 'security');
                $downloadSni = $security === 'reality' ? data_get($download, 'realitySettings.serverName')
                    : ($security === 'tls' ? data_get($download, 'tlsSettings.serverName') : null);
                $inner['downloadTargetHost'] = $address;
                $inner['downloadTargetPort'] = self::xhttpNativeString(data_get($download, 'port', 443), 'downloadSettings.port');
                $inner['downloadServerName'] = in_array($security, ['tls', 'reality'], true)
                    ? self::xhttpHost($downloadSni, $address) : '';
                $inner['downloadHTTPHost'] = self::xhttpHost(data_get($download, 'xhttpSettings.host'), $downloadSni, $address);
            }
        }

        if ($inner !== []) {
            $params[''] = (object)$inner;
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
