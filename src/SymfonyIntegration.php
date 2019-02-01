<?php

namespace updg\roadrunner\symfony;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpKernel\Kernel;
use updg\roadrunner\easy\HttpIntegrationInterface;

class SymfonyIntegration implements HttpIntegrationInterface
{
    /** @var Kernel */
    private $_kernel;

    /** @var string */
    private $_kernelClass;

    /** @var array Original $_SERVER data */
    private $originalServer = [];

    /** @var array Symfony env */
    private $_env = 'dev';

    /** @var bool Symfony debug */
    private $_debug = false;

    /** @var Request */
    private $_symfonyRequest;

    /** @var Response */
    private $_symfonyResponse;

    /**
     * SymfonyIntegration constructor.
     *
     * @param string          $kernelClass    Application kernel class. App\Kernel by default.
     * @param string|null     $env            Application environment (prod, dev).
     * @param bool|null       $debug          Debug state of Symfony.
     * @param array|bool|null $trustedProxies Trusted proxies for Symfony or false to disable check.
     * @param array|bool|null $trustedHosts   Trusted hosts for Symfony or false to disable check.
     */
    public function __construct(string $kernelClass = 'App\Kernel', $env = null, $debug = null, $trustedProxies = null, $trustedHosts = null)
    {
        $this->_kernelClass = $kernelClass;

        $env = $env ?? $_SERVER['APP_ENV'] ?? $_ENV['APP_ENV'] ?? 'dev';
        $debug = (bool)($debug ?? $_SERVER['APP_DEBUG'] ?? $_ENV['APP_DEBUG'] ?? ('prod' !== $env));

        if ($debug) {
            umask(0000);

            \Symfony\Component\Debug\Debug::enable();
        }

        if ($trustedProxies = $trustedProxies ?? $_SERVER['TRUSTED_PROXIES'] ?? $_ENV['TRUSTED_PROXIES'] ?? false) {
            Request::setTrustedProxies(explode(',', $trustedProxies), Request::HEADER_X_FORWARDED_ALL ^ Request::HEADER_X_FORWARDED_HOST);
        }

        if ($trustedHosts = $trustedHosts ?? $_SERVER['TRUSTED_HOSTS'] ?? $_ENV['TRUSTED_HOSTS'] ?? $trustedHosts ?? false) {
            Request::setTrustedHosts(explode(',', $trustedHosts));
        }
    }

    /**
     * @inheritdoc
     */
    public function init()
    {
        $this->originalServer = $_SERVER;
        $this->_kernel = new $this->_kernelClass($this->_env, $this->_debug);
    }

    /**
     * @inheritdoc
     */
    public function beforeRequest()
    {
    }

    /**
     * @inheritdoc
     */
    public function afterRequest()
    {
        $this->_kernel->terminate($this->_symfonyRequest, $this->_symfonyResponse);
    }

    /**
     * @inheritdoc
     */
    public function shutdown()
    {
        $this->_kernel->shutdown();
    }

    /**
     * @inheritdoc
     */
    public function processRequest(array $ctx, $body): array
    {
        $this->_symfonyRequest = $this->buildSymfonyRequest($ctx, $body);
        $this->_symfonyResponse = $this->_kernel->handle($this->_symfonyRequest);

        return $this->buildResponse($this->_symfonyResponse);
    }

    /**
     * Building Symfony request based of RR request data.
     *
     * @param array       $ctx  RR request context.
     * @param string|null $body Body of RR request.
     *
     * @return Request Symfony request.
     */
    private function buildSymfonyRequest(array $ctx, $body): Request
    {
        $_SERVER = $this->configureServer($ctx);

        parse_str($ctx['rawQuery'], $query);

        $request = new Request(
            $query,
            $ctx['parsed'] ? json_decode($body, true) : [],
            $ctx['attributes'],
            $ctx['cookies'],
            $ctx['uploads'] ? $this->prepareFiles($ctx['uploads']) : [],
            $_SERVER,
            $body
        );

        return $request;
    }

    /**
     * Building RR response request based of Symfony response.
     *
     * @param Response $response Symfony response
     *
     * @return array Response array for HttpClient
     */
    private function buildResponse(Response $response): array
    {
        $body = '';
        if ($response instanceof BinaryFileResponse) {
            $body = file_get_contents($response->getFile()->getPathname());
        } else {
            if ($response instanceof StreamedResponse) {
                ob_start(function ($buffer) use (&$body) {
                    $body .= $buffer;

                    return '';
                });

                $response->sendContent();
                ob_end_clean();
            } else {
                $body = $response->getContent();
            }
        }

        $headers = $response->headers->all();
        if (!isset($headers['Set-Cookie']) && !isset($headers['set-sookie'])) {
            $cookies = $response->headers->getCookies();
            if (!empty($cookies)) {
                $headers['Set-Cookie'] = [];
                foreach ($cookies as $cookie) {
                    $headers['Set-Cookie'][] = $cookie->__toString();
                }
            }
        }

        return ['status' => $response->getStatusCode(), 'body' => $body, 'headers' => $headers];
    }

    /**
     * Returns altered copy of _SERVER variable. Sets ip-address,
     * request-time and other values.
     *
     * @param array $ctx
     * @return array
     */
    private function configureServer(array $ctx): array
    {
        $server = $this->originalServer;
        $server['REQUEST_TIME'] = time();
        $server['REQUEST_TIME_FLOAT'] = microtime(true);
        $server['REMOTE_ADDR'] = $ctx['attributes']['ipAddress'] ?? $ctx['remoteAddr'] ?? '127.0.0.1';
        $server['REMOTE_ADDR'] = $ctx['attributes']['ipAddress'] ?? $ctx['remoteAddr'] ?? '127.0.0.1';
        $server['SERVER_PROTOCOL'] = $this->fetchProtocolVersion($ctx['protocol']);

        $server['HTTP_USER_AGENT'] = '';
        foreach ($ctx['headers'] as $key => $value) {
            $key = strtoupper(str_replace('-', '_', $key));
            if (\in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'])) {
                $server[$key] = implode(', ', $value);
            } else {
                $server['HTTP_' . $key] = implode(', ', $value);
            }
        }

        return $server;
    }

    /**
     * Normalize HTTP protocol version to valid values
     *
     * @param string $version
     * @return string
     */
    private function fetchProtocolVersion(string $version): string
    {
        $v = substr($version, 5);

        if ($v === '2.0') {
            return '2';
        }

        // Fallback for values outside of valid protocol versions
        if (!in_array($v, ['1.0', '1.1', '2'], true)) {
            return '1.1';
        }

        return $v;
    }

    /**
     * Converts RR request files array to $_FILES array style.
     *
     * @param array $uploads Array of files from RR request
     * @return array $_FILES style array
     */
    private function prepareFiles(array $uploads)
    {
        $files = [
            'name' => [],
            'type' => [],
            'tmp_name' => [],
            'error' => [],
            'size' => []
        ];

        foreach ($uploads as $key => $file) {
            $files['name'][$key] = $file['name'];
            $files['type'][$key] = $file['mine'];
            $files['tmp_name'][$key] = $file['tmpName'];
            $files['error'][$key] = $file['error'];
            $files['size'][$key] = $file['size'];
        }

        return $files;
    }
}
